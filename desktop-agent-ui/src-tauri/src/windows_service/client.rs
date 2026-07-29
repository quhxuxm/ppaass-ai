use super::*;

pub(crate) fn start_agent_via_windows_service(
    config_path: String,
    logs: &UiLogBuffer,
) -> Result<AgentState, String> {
    verify_interactive_installation_is_protected()?;
    trusted_windows_wintun_path()?;
    let (config_path, config_root) = canonical_managed_config_path(&config_path)?;
    ensure_windows_service_available(logs, &config_root)?;
    let response = send_service_request(&ServiceRequest::Start {
        config_path: config_path.to_string_lossy().to_string(),
    })?;
    service_state_response(response)
}

pub(crate) fn stop_agent_via_windows_service() -> Result<AgentState, String> {
    let response = send_service_request(&ServiceRequest::Stop)?;
    service_state_response(response)
}

pub(crate) fn windows_service_state() -> Result<AgentState, String> {
    let response = send_service_request(&ServiceRequest::State)?;
    service_state_response(response)
}

pub(crate) fn windows_service_auth_status() -> Result<Option<VerifiedProxyAuthStatus>, String> {
    if !windows_service_matches_current_exe().unwrap_or(false)
        || !windows_service_is_running().unwrap_or(false)
    {
        return Ok(None);
    }
    let response = send_service_request(&ServiceRequest::State)?;
    if response.ok {
        Ok(response.auth_status)
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "Agent 服务请求失败".to_string()))
    }
}

pub(crate) fn windows_service_is_running() -> Result<bool, String> {
    let output = match run_sc_capture(["query", SERVICE_NAME]) {
        Ok(output) => output,
        Err(error) if error.contains("1060") => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(output.lines().any(|line| {
        let line = line.to_ascii_uppercase();
        line.contains("STATE") && line.contains("RUNNING")
    }))
}

pub(crate) fn windows_service_matches_current_exe() -> Result<bool, String> {
    let output = run_sc_capture(["qc", SERVICE_NAME])?;
    let command_line = parse_sc_binary_path(&output)
        .ok_or_else(|| "无法读取 PPAASS Agent Windows Service 路径".to_string())?;
    if !command_line.contains(SERVICE_ARG) {
        return Ok(false);
    }

    let Some(service_exe_path) = extract_service_exe_path(command_line) else {
        return Ok(false);
    };

    let current_exe = std::env::current_exe().map_err(|err| format!("定位 UI 程序失败：{err}"))?;
    let service_exe = PathBuf::from(service_exe_path);
    Ok(normalized_path_for_compare(&current_exe) == normalized_path_for_compare(&service_exe))
}

pub(crate) fn send_service_request(request: &ServiceRequest) -> Result<ServiceResponse, String> {
    let addr = SERVICE_IPC_ADDR
        .parse::<SocketAddr>()
        .map_err(|err| format!("服务 IPC 地址无效：{err}"))?;
    let token = UI_SERVICE_SESSION_TOKEN
        .lock()
        .map_err(|_| "Windows Service 会话令牌锁已损坏".to_string())?
        .as_ref()
        .cloned()
        .ok_or_else(|| "Windows Service 会话未授权，请重新登录".to_string())?;
    send_service_request_to(addr, request, &token)
}

pub(crate) fn send_service_request_to(
    addr: SocketAddr,
    request: &ServiceRequest,
    auth_token: &str,
) -> Result<ServiceResponse, String> {
    let payload = encode_service_request(request, auth_token)?;

    // The UI calls this function from Tauri's blocking worker pool. A standard loopback
    // socket avoids creating and tearing down a Tokio runtime for every telemetry poll and
    // preserves the reliable Windows connect_timeout behavior used by the original IPC path.
    let mut stream =
        StdTcpStream::connect_timeout(&addr, SERVICE_IPC_CONNECT_TIMEOUT).map_err(|err| {
            if err.kind() == std::io::ErrorKind::TimedOut {
                "连接 Agent 服务超时".to_string()
            } else {
                format!("无法连接 Agent 服务：{err}")
            }
        })?;
    stream
        .set_read_timeout(Some(SERVICE_IPC_IO_TIMEOUT))
        .map_err(|err| format!("设置服务 IPC 读超时失败：{err}"))?;
    stream
        .set_write_timeout(Some(SERVICE_IPC_IO_TIMEOUT))
        .map_err(|err| format!("设置服务 IPC 写超时失败：{err}"))?;

    stream
        .write_all(&payload)
        .map_err(|err| format!("发送服务请求失败：{err}"))?;
    let _ = stream.shutdown(TcpShutdown::Write);

    let mut response = Vec::new();
    stream
        .take(MAX_SERVICE_IPC_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)
        .map_err(|err| format!("读取服务响应失败：{err}"))?;
    if response.len() as u64 > MAX_SERVICE_IPC_RESPONSE_BYTES {
        return Err("Agent 服务响应过大，已拒绝处理".to_string());
    }
    serde_json::from_slice(&response).map_err(|err| format!("解析服务响应失败：{err}"))
}

pub(crate) fn encode_service_request(
    request: &ServiceRequest,
    auth_token: &str,
) -> Result<Vec<u8>, String> {
    validate_service_token_format(auth_token)?;
    let payload = serde_json::to_vec(&ServiceRequestEnvelopeRef {
        auth_token,
        request,
    })
    .map_err(|err| format!("编码服务请求失败：{err}"))?;
    if payload.len() as u64 > MAX_SERVICE_IPC_REQUEST_BYTES {
        return Err("服务请求过大，已拒绝发送".to_string());
    }
    Ok(payload)
}

pub(crate) fn install_and_start_windows_service(config_root: PathBuf) -> Result<(), String> {
    trusted_service_executable()?;
    trusted_windows_wintun_path()?;
    let config_root = canonical_managed_config_root_dir(&config_root)?;
    let exe = std::env::current_exe().map_err(|err| format!("定位 UI 程序失败：{err}"))?;
    let bin_path = format!(
        "\"{}\" {SERVICE_ARG} {SERVICE_CONFIG_ROOT_ARG} \"{}\"",
        exe.display(),
        config_root.display()
    );

    if run_sc(["query", SERVICE_NAME]).is_err() {
        run_sc([
            "create",
            SERVICE_NAME,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "DisplayName=",
            SERVICE_DISPLAY_NAME,
        ])?;
    } else {
        stop_windows_service_if_running()?;
        run_sc([
            "config",
            SERVICE_NAME,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
        ])?;
    }

    match run_sc(["start", SERVICE_NAME]) {
        Ok(()) => Ok(()),
        Err(err) if err.contains("1056") || err.contains("already running") => Ok(()),
        Err(err) => Err(err),
    }
}

pub(crate) fn run_windows_service(config_root: PathBuf) -> Result<(), String> {
    trusted_service_executable()?;
    trusted_windows_wintun_path()?;
    let config_root = canonical_managed_config_root_dir(&config_root)?;
    SERVICE_CONFIG_ROOT
        .set(config_root)
        .map_err(|_| "Windows Service 受管配置目录被重复初始化".to_string())?;
    service_dispatcher::start(SERVICE_NAME, windows_service_entrypoint())
        .map_err(|err| format!("启动 Windows Service dispatcher 失败：{err}"))
}

pub(crate) fn service_config_root_from_args() -> Result<PathBuf, String> {
    let mut args = std::env::args_os();
    while let Some(arg) = args.next() {
        if arg == SERVICE_CONFIG_ROOT_ARG {
            return args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "Windows Service 缺少受管配置目录参数".to_string());
        }
    }
    Err("Windows Service 缺少受管配置目录参数".to_string())
}

pub(crate) fn service_state_response(response: ServiceResponse) -> Result<AgentState, String> {
    if response.ok {
        response
            .state
            .ok_or_else(|| "服务响应缺少 Agent 状态".to_string())
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "Agent 服务请求失败".to_string()))
    }
}

pub(crate) fn ensure_windows_service_available(
    logs: &UiLogBuffer,
    config_root: &Path,
) -> Result<(), String> {
    let service_is_current = windows_service_matches_installation(config_root).unwrap_or(false);
    if service_is_current && send_service_request(&ServiceRequest::State).is_ok() {
        return Ok(());
    }

    if service_is_current {
        logs.push("正在请求启动 PPAASS Agent Windows Service");
    } else if run_sc(["query", SERVICE_NAME]).is_ok() {
        logs.push("PPAASS Agent Windows Service 指向旧程序，正在请求管理员权限更新服务");
    } else {
        logs.push("正在请求安装 PPAASS Agent Windows Service");
    }
    launch_elevated_service_installer(config_root)?;

    let deadline = Instant::now() + Duration::from_secs(35);
    while Instant::now() < deadline {
        let service_is_current = windows_service_matches_installation(config_root).unwrap_or(false);
        if service_is_current && send_service_request(&ServiceRequest::State).is_ok() {
            logs.push("PPAASS Agent Windows Service 已就绪");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    Err("PPAASS Agent Windows Service 启动超时".to_string())
}
