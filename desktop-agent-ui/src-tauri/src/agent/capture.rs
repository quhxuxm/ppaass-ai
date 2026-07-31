use super::*;

pub fn packet_capture_runtime_status(
    runtime: &AgentRuntime,
) -> Result<PacketCaptureRuntimeStatus, String> {
    #[cfg(windows)]
    if windows_service_matches_current_exe().unwrap_or(false) {
        return packet_capture_service_request(&ServiceRequest::PacketCaptureStatus);
    }

    packet_capture_runtime_status_local(runtime)
}

pub fn packet_capture_runtime_status_local(
    runtime: &AgentRuntime,
) -> Result<PacketCaptureRuntimeStatus, String> {
    let guard = runtime
        .agent
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?;
    let Some(agent) = guard.as_ref() else {
        return Ok(PacketCaptureRuntimeStatus {
            available: false,
            enabled: false,
            file: None,
        });
    };
    Ok(PacketCaptureRuntimeStatus {
        available: true,
        enabled: agent.packet_capture.is_enabled(),
        file: Some(agent.packet_capture.file().to_string_lossy().to_string()),
    })
}

pub fn set_packet_capture_runtime_enabled(
    runtime: &AgentRuntime,
    enabled: bool,
) -> Result<PacketCaptureRuntimeStatus, String> {
    #[cfg(windows)]
    if windows_service_matches_current_exe().unwrap_or(false) {
        return packet_capture_service_request(&ServiceRequest::SetPacketCapture { enabled });
    }

    set_packet_capture_runtime_enabled_local(runtime, enabled)
}

pub fn set_packet_capture_runtime_enabled_local(
    runtime: &AgentRuntime,
    enabled: bool,
) -> Result<PacketCaptureRuntimeStatus, String> {
    let controller = {
        let guard = runtime
            .agent
            .lock()
            .map_err(|_| "进程状态锁已损坏".to_string())?;
        guard
            .as_ref()
            .map(|agent| agent.packet_capture.clone())
            .ok_or_else(|| "Agent 未运行，请先启动 Agent".to_string())?
    };
    controller
        .set_enabled(enabled)
        .map_err(|error| format!("{}抓包失败：{error}", if enabled { "开启" } else { "关闭" }))?;
    runtime
        .packet_capture_enabled
        .store(controller.is_enabled(), Ordering::Release);
    Ok(PacketCaptureRuntimeStatus {
        available: true,
        enabled: controller.is_enabled(),
        file: Some(controller.file().to_string_lossy().to_string()),
    })
}

pub fn clear_packet_capture_runtime(
    runtime: &AgentRuntime,
    config_path: Option<String>,
) -> Result<PacketCaptureRuntimeStatus, String> {
    #[cfg(windows)]
    if windows_service_matches_current_exe().unwrap_or(false) {
        return packet_capture_service_request(&ServiceRequest::ClearPacketCapture {
            config_path: config_path.clone(),
        });
    }

    clear_packet_capture_runtime_local(runtime, config_path)
}

pub fn clear_packet_capture_runtime_local(
    runtime: &AgentRuntime,
    config_path: Option<String>,
) -> Result<PacketCaptureRuntimeStatus, String> {
    let running_controller = runtime
        .agent
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?
        .as_ref()
        .map(|agent| agent.packet_capture.clone());
    let available = running_controller.is_some();

    let controller = match running_controller {
        Some(controller) => controller,
        None => {
            let config_path = match config_path.filter(|value| !value.trim().is_empty()) {
                Some(value) => PathBuf::from(value),
                None => locate_config_path()
                    .ok_or_else(|| "找不到 Agent 配置文件。请确认 agent.toml 存在。".to_string())?,
            };
            let config = desktop_agent_be::config::AgentConfig::load(&config_path)
                .map_err(|error| format!("加载 Agent 配置失败：{error}"))?;
            PacketCaptureController::new(resolve_agent_output_path(
                &config_path,
                &config.tun.packet_capture.file,
            ))
        }
    };
    controller
        .clear()
        .map_err(|error| format!("清空抓包文件失败：{error}"))?;
    Ok(PacketCaptureRuntimeStatus {
        available,
        enabled: controller.is_enabled(),
        file: Some(controller.file().to_string_lossy().to_string()),
    })
}

#[cfg(windows)]
pub fn packet_capture_service_request(
    request: &ServiceRequest,
) -> Result<PacketCaptureRuntimeStatus, String> {
    let response = send_service_request(request)?;
    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| "Agent 服务抓包操作失败".to_string()));
    }
    response
        .packet_capture
        .ok_or_else(|| "Agent 服务未返回抓包状态".to_string())
}
