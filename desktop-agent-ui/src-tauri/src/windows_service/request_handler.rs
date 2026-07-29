use super::*;

pub(crate) fn service_request_is_mutating(request: &ServiceRequest) -> bool {
    matches!(
        request,
        ServiceRequest::Start { .. }
            | ServiceRequest::Stop
            | ServiceRequest::SetLogLevel { .. }
            | ServiceRequest::SetPacketCapture { .. }
            | ServiceRequest::ClearPacketCapture { .. }
    )
}

pub(crate) fn handle_service_request(
    runtime: &AgentRuntime,
    request: ServiceRequest,
) -> ServiceResponse {
    match request {
        ServiceRequest::Start { config_path } => match start_service_agent(runtime, &config_path) {
            Ok(state) => service_state_ok(runtime, state),
            Err(err) => service_error(err),
        },
        ServiceRequest::Stop => match stop_service_agent(runtime) {
            Ok(state) => service_state_ok(runtime, state),
            Err(err) => service_error(err),
        },
        ServiceRequest::State => match agent_state(runtime) {
            Ok(state) => service_state_ok(runtime, state),
            Err(err) => service_error(err),
        },
        ServiceRequest::Traffic => ServiceResponse {
            ok: true,
            state: None,
            traffic: Some(agent_traffic_snapshot()),
            dns_records: None,
            packet_capture: None,
            auth_status: None,
            error: None,
        },
        ServiceRequest::DnsRecords => ServiceResponse {
            ok: true,
            state: None,
            traffic: None,
            dns_records: Some(desktop_agent_be::telemetry::dns_resolution_records()),
            packet_capture: None,
            auth_status: None,
            error: None,
        },
        ServiceRequest::SetLogLevel { log_level } => match runtime.logs.set_log_level(&log_level) {
            Ok(()) => match agent_state(runtime) {
                Ok(state) => service_state_ok(runtime, state),
                Err(err) => service_error(err),
            },
            Err(err) => service_error(err),
        },
        ServiceRequest::PacketCaptureStatus => {
            service_packet_capture_result(packet_capture_runtime_status_local(runtime))
        }
        ServiceRequest::SetPacketCapture { enabled } => service_packet_capture_result(
            set_packet_capture_runtime_enabled_local(runtime, enabled),
        ),
        ServiceRequest::ClearPacketCapture { config_path } => {
            let requested_path = config_path.unwrap_or_else(service_root_config_path);
            match validate_service_config_path(&requested_path) {
                Ok(config_path) => {
                    service_packet_capture_result(clear_packet_capture_runtime_local(
                        runtime,
                        Some(config_path.to_string_lossy().to_string()),
                    ))
                }
                Err(error) => service_error(error),
            }
        }
    }
}

pub(crate) fn start_service_agent(
    runtime: &AgentRuntime,
    config_path: &str,
) -> Result<AgentState, String> {
    let (config_path, login_binding, proxy_addresses) =
        validate_authorized_service_config_path(config_path)?;
    let state = start_agent_inner(runtime, config_path, proxy_addresses, false)?;
    if !state.running {
        return Err("Windows Service 启动 Agent 后未进入运行状态".to_string());
    }
    if let Err(persist_error) = persist_service_desired_running(Some(&login_binding)) {
        return match stop_embedded_agent(runtime) {
            Ok(()) => Err(format!(
                "无法持久保存 Agent 运行请求，已回滚本次启动：{persist_error}"
            )),
            Err(stop_error) => Err(format!(
                "无法持久保存 Agent 运行请求（{persist_error}），且回滚 Agent 失败（{stop_error}）"
            )),
        };
    }
    Ok(state)
}

pub(crate) fn stop_service_agent(runtime: &AgentRuntime) -> Result<AgentState, String> {
    // Persist the user's explicit stop before touching the running process. If
    // the Service crashes at any later point it must never resurrect an Agent
    // that the user already asked to stop.
    persist_service_desired_running(None)?;
    stop_embedded_agent(runtime)?;
    agent_state(runtime)
}

pub(crate) fn validate_service_config_path(config_path: &str) -> Result<PathBuf, String> {
    let config_root = SERVICE_CONFIG_ROOT
        .get()
        .ok_or_else(|| "Windows Service 未配置受管 Agent 数据目录".to_string())?;
    validate_service_config_path_for_root(config_path, config_root)
}

pub(crate) fn validate_authorized_service_config_path(
    config_path: &str,
) -> Result<(PathBuf, ServiceLoginBinding, Vec<String>), String> {
    let config_root = SERVICE_CONFIG_ROOT
        .get()
        .ok_or_else(|| "Windows Service 未配置受管 Agent 数据目录".to_string())?;
    let canonical = validate_service_config_path_for_root(config_path, config_root)?;
    let app_data_dir = canonical
        .parent()
        .ok_or_else(|| "Windows Service Agent 配置缺少父目录".to_string())?;
    let raw = fs::read_to_string(&canonical)
        .map_err(|error| format!("读取 Windows Service Agent 配置失败：{error}"))?;
    let config = toml::from_str::<toml::Value>(&raw)
        .map_err(|error| format!("Windows Service Agent 配置格式无效：{error}"))?;

    let credentials_dir = service_credentials_dir_for_root(config_root)?;
    let persisted = load_persisted_agent_login_from_dir(&credentials_dir)?
        .ok_or_else(|| "Windows Service 找不到持久登录授权，请重新登录".to_string())?;
    validate_managed_proxy_addresses(&persisted.proxy_addresses, false)?;
    let config_username = service_config_string(&config, &["username"]).unwrap_or_default();
    if config_username != persisted.account.username {
        return Err("Windows Service 配置用户与持久登录用户不一致".to_string());
    }

    let configured_private_key = service_config_string(&config, &["private_key_path"])
        .ok_or_else(|| "Windows Service Agent 配置缺少托管私钥，请先登录".to_string())?;
    let configured_proxy_identity =
        service_config_string(&config, &["proxy_identity_public_key_path"]).ok_or_else(|| {
            "Windows Service Agent 配置缺少托管 Proxy 身份公钥，请先登录".to_string()
        })?;
    ensure_same_canonical_path(
        &resolve_configured_path(app_data_dir, configured_private_key),
        &persisted.private_key_path,
        "私钥",
    )?;
    ensure_same_canonical_path(
        &resolve_configured_path(app_data_dir, configured_proxy_identity),
        &persisted.proxy_identity_public_key_path,
        "Proxy 身份公钥",
    )?;

    Ok((
        canonical,
        ServiceLoginBinding {
            username: persisted.account.username,
            key_version: persisted.account.key_version,
        },
        persisted.proxy_addresses,
    ))
}

pub(crate) fn resolve_configured_path(app_data_dir: &Path, configured_path: &str) -> PathBuf {
    let configured_path = Path::new(configured_path);
    if configured_path.is_absolute() {
        configured_path.to_path_buf()
    } else {
        app_data_dir.join(configured_path)
    }
}

pub(crate) fn ensure_same_canonical_path(
    configured: &Path,
    persisted: &Path,
    credential_name: &str,
) -> Result<(), String> {
    let configured = fs::canonicalize(configured)
        .map_err(|error| format!("无法定位 Windows Service 配置中的{credential_name}：{error}"))?;
    let persisted = fs::canonicalize(persisted)
        .map_err(|error| format!("无法定位 Windows Service 持久登录{credential_name}：{error}"))?;
    if normalized_path_for_compare(&configured) != normalized_path_for_compare(&persisted) {
        return Err(format!(
            "Windows Service 配置中的{credential_name}与持久登录凭据不一致"
        ));
    }
    Ok(())
}

pub(crate) fn validate_service_config_path_for_root(
    config_path: &str,
    config_root: &Path,
) -> Result<PathBuf, String> {
    let (canonical, app_data_dir) = canonical_managed_config_path(config_path)?;
    let expected_root = canonical_managed_config_root_dir(config_root)?;
    if normalized_path_for_compare(&app_data_dir) != normalized_path_for_compare(&expected_root) {
        return Err("Windows Service Agent 配置不属于当前受管用户".to_string());
    }

    let raw = fs::read_to_string(&canonical)
        .map_err(|err| format!("读取 Windows Service Agent 配置失败：{err}"))?;
    let config = toml::from_str::<toml::Value>(&raw)
        .map_err(|err| format!("Windows Service Agent 配置格式无效：{err}"))?;
    let username = service_config_string(&config, &["username"]).unwrap_or_default();
    if username.trim().is_empty() {
        return Err("Windows Service Agent 配置缺少托管用户名，请先登录".to_string());
    }
    let private_key_path = service_config_string(&config, &["private_key_path"])
        .ok_or_else(|| "Windows Service Agent 配置缺少托管私钥，请先登录".to_string())?;
    validate_managed_private_key_path(&app_data_dir, private_key_path)?;
    let proxy_identity_public_key_path =
        service_config_string(&config, &["proxy_identity_public_key_path"]).ok_or_else(|| {
            "Windows Service Agent 配置缺少托管 Proxy 身份公钥，请先登录".to_string()
        })?;
    validate_managed_proxy_identity_public_key_path(&app_data_dir, proxy_identity_public_key_path)?;

    if let Some(configured_wintun) = service_config_string(&config, &["tun", "wintun_file"]) {
        let trusted_wintun = trusted_windows_wintun_path()?;
        let configured_is_legacy_name = configured_wintun.eq_ignore_ascii_case("wintun.dll");
        let configured_is_trusted_absolute = Path::new(configured_wintun).is_absolute()
            && fs::canonicalize(configured_wintun).is_ok_and(|path| {
                normalized_path_for_compare(&path) == normalized_path_for_compare(&trusted_wintun)
            });
        if !configured_is_legacy_name && !configured_is_trusted_absolute {
            return Err("Windows Service 只允许使用可信安装目录中的 wintun.dll".to_string());
        }
    }

    for path in [
        &["log_dir"][..],
        &["log_file"][..],
        &["tun", "route_state_file"][..],
        &["tun", "dns_state_file"][..],
        &["tun", "packet_capture", "file"][..],
    ] {
        if let Some(value) = service_config_string(&config, path) {
            validate_service_managed_path(&app_data_dir, value)?;
        }
    }
    Ok(canonical)
}

pub(crate) fn canonical_managed_config_path(
    config_path: &str,
) -> Result<(PathBuf, PathBuf), String> {
    let canonical = fs::canonicalize(config_path)
        .map_err(|err| format!("无法定位 Windows Service Agent 配置：{err}"))?;
    if canonical.file_name().and_then(|value| value.to_str()) != Some("agent.toml") {
        return Err("Windows Service 只允许使用 AppData 根 agent.toml".to_string());
    }
    let app_data_dir = canonical
        .parent()
        .ok_or_else(|| "Windows Service Agent 配置缺少父目录".to_string())?
        .to_path_buf();
    if !is_expected_windows_app_data_dir(&app_data_dir) {
        return Err("Windows Service Agent 配置不在受管 AppData 目录".to_string());
    }
    Ok((canonical, app_data_dir))
}

pub(crate) fn canonical_managed_config_root_dir(config_root: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(config_root)
        .map_err(|err| format!("无法定位 Windows Service 受管配置目录：{err}"))?;
    if !is_expected_windows_app_data_dir(&canonical) {
        return Err("Windows Service 受管配置目录不是 Agent AppData".to_string());
    }
    Ok(canonical)
}

pub(crate) fn service_root_config_path() -> String {
    SERVICE_CONFIG_ROOT
        .get()
        .map(|root| root.join("agent.toml").to_string_lossy().to_string())
        .unwrap_or_default()
}
