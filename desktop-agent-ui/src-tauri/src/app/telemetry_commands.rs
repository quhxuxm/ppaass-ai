use super::*;

#[tauri::command]
pub(crate) async fn run_connectivity_tests(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    path: Option<String>,
) -> Result<ConnectivityReport, String> {
    let runtime = runtime.inner().clone();
    run_blocking("诊断", move || {
        runtime.require_authenticated()?;
        run_connectivity_tests_blocking(path)
    })
    .await
}

#[tauri::command]
pub(crate) async fn get_network_traffic_snapshot(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<NetworkTrafficSnapshot, String> {
    let runtime = runtime.inner().clone();
    run_blocking("读取流量", move || {
        runtime.require_authenticated()?;
        get_network_traffic_snapshot_inner()
    })
    .await
}

#[tauri::command]
pub(crate) async fn get_dns_resolution_records(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<Vec<desktop_agent_be::telemetry::DnsResolutionRecord>, String> {
    let runtime = runtime.inner().clone();
    run_blocking("读取 DNS 解析记录", move || {
        runtime.require_authenticated()?;
        get_dns_resolution_records_inner()
    })
    .await
}

#[tauri::command]
pub(crate) async fn get_packet_capture(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    config_path: Option<String>,
    limit: Option<usize>,
) -> Result<PacketCaptureReport, String> {
    let runtime = runtime.inner().clone();
    run_blocking("读取抓包结果", move || {
        require_packet_capture_permission(&runtime)?;
        let config_path = match config_path.filter(|value| !value.trim().is_empty()) {
            Some(value) => PathBuf::from(value),
            None => locate_config_path()
                .ok_or_else(|| "找不到 Agent 配置文件。请确认 agent.toml 存在。".to_string())?,
        };
        let config = desktop_agent_be::config::AgentConfig::load(&config_path)
            .map_err(|error| format!("加载 Agent 配置失败：{error}"))?;
        let capture_path = resolve_agent_output_path(&config_path, &config.tun.packet_capture.file);
        let proxy_listen_port = config
            .listen_addr
            .rsplit_once(':')
            .and_then(|(_, port)| port.trim().parse::<u16>().ok());
        read_packet_capture(&capture_path, limit, proxy_listen_port)
    })
    .await
}

#[tauri::command]
pub(crate) async fn get_packet_capture_runtime_status(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<PacketCaptureRuntimeStatus, String> {
    let runtime = runtime.inner().clone();
    run_blocking("读取抓包运行状态", move || {
        require_packet_capture_permission(&runtime)?;
        packet_capture_runtime_status(&runtime)
    })
    .await
}

#[tauri::command]
pub(crate) async fn set_packet_capture_enabled(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    enabled: bool,
) -> Result<PacketCaptureRuntimeStatus, String> {
    let runtime = runtime.inner().clone();
    run_blocking("切换抓包运行状态", move || {
        require_packet_capture_permission(&runtime)?;
        set_packet_capture_runtime_enabled(&runtime, enabled)
    })
    .await
}

#[tauri::command]
pub(crate) async fn clear_packet_capture(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    config_path: Option<String>,
) -> Result<PacketCaptureRuntimeStatus, String> {
    let runtime = runtime.inner().clone();
    run_blocking("清空抓包文件", move || {
        require_packet_capture_permission(&runtime)?;
        clear_packet_capture_runtime(&runtime, config_path)
    })
    .await
}

fn require_packet_capture_permission(runtime: &AgentRuntime) -> Result<(), String> {
    runtime
        .require_authenticated_session()?
        .account
        .require_permission(AGENT_PACKET_CAPTURE_PERMISSION)
}
