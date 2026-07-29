use super::*;

pub(crate) fn macos_tun_helper_status(
    config: &desktop_agent_be::config::AgentConfig,
) -> MacosTunHelperStatus {
    let socket_path = macos_tun_helper_socket(config);
    let install_path = Path::new(TUN_HELPER_INSTALL_PATH);
    let plist_path = Path::new(TUN_HELPER_PLIST_PATH);
    if !install_path.is_file() || !plist_path.is_file() {
        return MacosTunHelperStatus::Missing;
    }

    if !macos_tun_helper_plist_matches(config).unwrap_or(false) {
        return MacosTunHelperStatus::Outdated;
    }

    match macos_tun_helper_protocol_version(socket_path) {
        Ok(version) if version == TUN_HELPER_PROTOCOL_VERSION => MacosTunHelperStatus::Current,
        Ok(_) => MacosTunHelperStatus::Outdated,
        Err(_) if macos_tun_helper_ping(socket_path).is_ok() => {
            // Ping is supported by legacy helpers. If ping works but the
            // version handshake does not, this is an old protocol.
            MacosTunHelperStatus::Outdated
        }
        Err(_) => MacosTunHelperStatus::NeedsRestart,
    }
}

pub(crate) fn macos_tun_helper_socket_ready(socket_path: &str) -> bool {
    macos_tun_helper_ping(socket_path).is_ok()
}

pub(crate) fn macos_tun_helper_ping(socket_path: &str) -> Result<(), String> {
    match send_macos_tun_helper_request(
        socket_path,
        &TunHelperRequest::Ping,
        Duration::from_millis(700),
    )? {
        TunHelperResponse::Pong => Ok(()),
        TunHelperResponse::Error { message } => {
            Err(format!("TUN helper probe 返回错误：{message}"))
        }
        TunHelperResponse::Ok => Err("TUN helper probe 返回了意外响应：ok".to_string()),
        TunHelperResponse::HelperInfo { .. } => {
            Err("TUN helper probe 返回了意外响应：helper_info".to_string())
        }
        TunHelperResponse::TunStarted(_) => {
            Err("TUN helper probe 返回了意外响应：tun_started".to_string())
        }
    }
}

pub(crate) fn macos_tun_helper_protocol_version(socket_path: &str) -> Result<u32, String> {
    match send_macos_tun_helper_request(
        socket_path,
        &TunHelperRequest::GetHelperInfo,
        Duration::from_millis(700),
    )? {
        TunHelperResponse::HelperInfo { protocol_version } => Ok(protocol_version),
        TunHelperResponse::Error { message } => {
            Err(format!("TUN helper 版本握手返回错误：{message}"))
        }
        TunHelperResponse::Pong => Err("TUN helper 版本握手返回了意外响应：pong".to_string()),
        TunHelperResponse::Ok => Err("TUN helper 版本握手返回了意外响应：ok".to_string()),
        TunHelperResponse::TunStarted(_) => {
            Err("TUN helper 版本握手返回了意外响应：tun_started".to_string())
        }
    }
}

pub(crate) fn request_macos_tun_helper_cleanup(
    socket_path: &str,
    state_paths: &MacosTunHelperStatePaths,
) -> Result<(), String> {
    let request = TunHelperRequest::CleanupStale {
        route_state_file: Some(state_paths.route.to_string_lossy().into_owned()),
        dns_state_file: Some(state_paths.dns.to_string_lossy().into_owned()),
    };
    validate_macos_tun_helper_cleanup_response(send_macos_tun_helper_request(
        socket_path,
        &request,
        TUN_HELPER_CONTROL_TIMEOUT,
    )?)
}

pub(crate) fn validate_macos_tun_helper_cleanup_response(
    response: TunHelperResponse,
) -> Result<(), String> {
    match response {
        TunHelperResponse::Ok => Ok(()),
        TunHelperResponse::Error { message } => {
            Err(format!("TUN helper 安全清理返回错误：{message}"))
        }
        TunHelperResponse::Pong => Err("TUN helper 安全清理返回了意外响应：pong".to_string()),
        TunHelperResponse::HelperInfo { .. } => {
            Err("TUN helper 安全清理返回了意外响应：helper_info".to_string())
        }
        TunHelperResponse::TunStarted(_) => {
            Err("TUN helper 安全清理返回了意外响应：tun_started".to_string())
        }
    }
}

pub(crate) fn send_macos_tun_helper_request(
    socket_path: &str,
    request: &TunHelperRequest,
    timeout: Duration,
) -> Result<TunHelperResponse, String> {
    if !Path::new(socket_path).exists() {
        return Err(format!("helper socket 不存在：{socket_path}"));
    }

    let mut stream = UnixStream::connect(socket_path)
        .map_err(|err| format!("连接 TUN helper 失败：socket={socket_path} error={err}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("设置 helper probe 读超时失败：{err}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("设置 helper probe 写超时失败：{err}"))?;

    exchange_macos_tun_helper_request(&mut stream, request)
}

pub(crate) fn exchange_macos_tun_helper_request(
    stream: &mut UnixStream,
    request: &TunHelperRequest,
) -> Result<TunHelperResponse, String> {
    let payload =
        serde_json::to_vec(request).map_err(|err| format!("序列化 TUN helper 请求失败：{err}"))?;
    let len = (payload.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .map_err(|err| format!("发送 TUN helper probe 失败：{err}"))?;
    stream
        .write_all(&payload)
        .map_err(|err| format!("发送 TUN helper probe 失败：{err}"))?;

    let mut marker = [0u8; 1];
    stream
        .read_exact(&mut marker)
        .map_err(|err| format!("读取 TUN helper probe marker 失败：{err}"))?;
    if marker != [1] {
        return Err(format!(
            "TUN helper probe marker 无效：{}",
            marker.first().copied().unwrap_or_default()
        ));
    }

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|err| format!("读取 TUN helper probe 响应长度失败：{err}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return Err(format!("TUN helper probe 响应过大：{len} bytes"));
    }

    let mut response = vec![0u8; len];
    stream
        .read_exact(&mut response)
        .map_err(|err| format!("读取 TUN helper probe 响应失败：{err}"))?;

    serde_json::from_slice::<TunHelperResponse>(&response)
        .map_err(|err| format!("解析 TUN helper probe 响应失败：{err}"))
}
