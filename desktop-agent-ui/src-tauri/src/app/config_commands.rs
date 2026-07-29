use super::*;

#[tauri::command]
pub(crate) async fn load_agent_config(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    path: Option<String>,
) -> Result<LoadedAgentConfig, String> {
    let runtime = runtime.inner().clone();
    let loaded = run_blocking("加载配置", move || {
        runtime.require_authenticated()?;
        load_agent_config_inner(&runtime, path)
    })
    .await?;
    #[cfg(any(windows, target_os = "macos"))]
    sync_tray_tun_checked(&app, loaded.summary.tun_enabled);
    Ok(loaded)
}

#[tauri::command]
pub(crate) async fn save_agent_config(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    path: String,
    raw: String,
) -> Result<LoadedAgentConfig, String> {
    let runtime = runtime.inner().clone();
    let loaded = run_blocking("保存配置", move || {
        runtime.require_authenticated()?;
        save_agent_config_inner(&runtime, path, raw)
    })
    .await?;
    #[cfg(any(windows, target_os = "macos"))]
    sync_tray_tun_checked(&app, loaded.summary.tun_enabled);
    Ok(loaded)
}

#[tauri::command]
pub(crate) async fn save_agent_config_summary(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    path: String,
    summary: AgentConfigSummary,
) -> Result<LoadedAgentConfig, String> {
    let runtime = runtime.inner().clone();
    let loaded = run_blocking("保存结构化配置", move || {
        save_agent_config_summary_inner(&runtime, path, summary)
    })
    .await?;
    #[cfg(any(windows, target_os = "macos"))]
    sync_tray_tun_checked(&app, loaded.summary.tun_enabled);
    Ok(loaded)
}

#[tauri::command]
pub(crate) async fn load_default_agent_config(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    path: Option<String>,
) -> Result<LoadedAgentConfig, String> {
    let runtime = runtime.inner().clone();
    run_blocking("加载默认配置", move || {
        let session = runtime.require_authenticated_session()?;
        prepare_config_for_account(
            load_default_config(&app, path.as_deref())?,
            &session.account,
        )
    })
    .await
}

#[tauri::command]
pub(crate) async fn get_agent_state(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentState, String> {
    let runtime = runtime.inner().clone();
    run_blocking("读取 Agent 状态", move || {
        runtime.require_authenticated()?;
        get_agent_state_inner(&runtime)
    })
    .await
}

#[tauri::command]
pub(crate) async fn start_agent(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    config_path: String,
) -> Result<AgentState, String> {
    let runtime = runtime.inner().clone();
    run_blocking("启动 Agent", move || {
        let session = runtime.require_authenticated_session()?;
        let config_path = current_ui_config_path(&runtime)
            .unwrap_or_else(|| make_absolute_path(Path::new(&config_path)));
        let candidate = load_config_from_path(&config_path)?;
        validate_config_candidate_against_trusted_baseline(&runtime, &session.account, &candidate)?;
        let loaded = apply_managed_credentials_to_config(
            &config_path,
            &session.account.username,
            &session.private_key_path,
            &session.proxy_identity_public_key_path,
        )?;
        remember_trusted_ui_config(&runtime, &loaded)?;
        start_agent_command(&runtime, loaded.path)
    })
    .await
}

#[tauri::command]
pub(crate) async fn stop_agent(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentState, String> {
    let runtime = runtime.inner().clone();
    run_blocking("停止 Agent", move || stop_agent_inner_command(&runtime)).await
}
