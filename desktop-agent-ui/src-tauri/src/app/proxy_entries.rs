use std::path::Path;
use std::time::Instant;

use common::AuthenticatedConnection;
use desktop_agent_be::yamux_session::proxy_connection::AgentClientConfig;
use protocol::DEFAULT_SPEED_TEST_DOWNLOAD_BYTES;

use super::*;

#[tauri::command]
pub(crate) async fn get_agent_proxy_entries(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentProxyEntrySelection, String> {
    let session = require_proxy_entry_session(runtime.inner())?;
    let token = session
        .agent_access_token
        .as_ref()
        .ok_or_else(|| "节点列表凭据缺失，请重新登录".to_string())?;
    let snapshot = fetch_agent_permission_snapshot(
        &session.proxy_registry_url,
        token.value.as_str(),
        &session.account.username,
    )
    .await
    .map_err(|failure| failure.message)?;
    ensure_selectable_snapshot(&snapshot)?;
    Ok(snapshot.proxy_entry_selection())
}

#[tauri::command]
pub(crate) async fn select_agent_proxy_entry_command(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    proxy_entry_ids: Vec<String>,
) -> Result<AgentProxyEntrySelection, String> {
    let session = require_proxy_entry_session(runtime.inner())?;
    let token = session
        .agent_access_token
        .as_ref()
        .ok_or_else(|| "节点切换凭据缺失，请重新登录".to_string())?;
    let expected_token = token.value.to_string();
    let snapshot = select_agent_proxy_entry_snapshot(
        &session.proxy_registry_url,
        &expected_token,
        &session.account.username,
        &proxy_entry_ids,
    )
    .await?;
    ensure_selectable_snapshot(&snapshot)?;
    apply_selected_proxy_entry(&app, runtime.inner(), &session, &expected_token, &snapshot).await?;
    Ok(snapshot.proxy_entry_selection())
}

#[tauri::command]
pub(crate) async fn speed_test_agent_proxy_entry(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    proxy_entry_id: String,
) -> Result<AgentProxyEntrySpeedResult, String> {
    let session = require_proxy_entry_session(runtime.inner())?;
    let token = session
        .agent_access_token
        .as_ref()
        .ok_or_else(|| "节点测速凭据缺失，请重新登录".to_string())?;
    let snapshot = fetch_agent_permission_snapshot(
        &session.proxy_registry_url,
        token.value.as_str(),
        &session.account.username,
    )
    .await
    .map_err(|failure| failure.message)?;
    ensure_selectable_snapshot(&snapshot)?;
    let entry = snapshot
        .proxy_entries
        .iter()
        .find(|entry| entry.proxy_entry_id == proxy_entry_id)
        .ok_or_else(|| "该 Proxy Entry 已不可用，请刷新列表".to_string())?;
    measure_proxy_entry(runtime.inner(), &session, entry).await
}

fn require_proxy_entry_session(
    runtime: &AgentRuntime,
) -> Result<AuthenticatedAgentSession, String> {
    let session = runtime.require_authenticated_session()?;
    if session.account_status != AgentAuthAccountStatus::Active {
        return Err("当前账号不可使用 Proxy Entry".to_string());
    }
    session
        .account
        .require_permission(AGENT_PROXY_ENTRY_SELECT_PERMISSION)?;
    Ok(session)
}

fn ensure_selectable_snapshot(
    snapshot: &crate::auth::AgentPermissionSnapshot,
) -> Result<(), String> {
    let has_permission = snapshot.role == "admin"
        || snapshot.permissions.as_ref().is_some_and(|permissions| {
            permissions
                .iter()
                .any(|permission| permission == AGENT_PROXY_ENTRY_SELECT_PERMISSION)
        });
    if !has_permission {
        return Err("当前账号没有自选 Proxy Entry 权限".to_string());
    }
    if snapshot.proxy_entries.is_empty() {
        return Err("暂无可用 Proxy Entry".to_string());
    }
    Ok(())
}

async fn apply_selected_proxy_entry(
    app: &tauri::AppHandle,
    runtime: &Arc<AgentRuntime>,
    expected: &AuthenticatedAgentSession,
    expected_token: &str,
    snapshot: &crate::auth::AgentPermissionSnapshot,
) -> Result<(), String> {
    let _operation = runtime.auth_operation.lock().await;
    let current = runtime.require_authenticated_session()?;
    if current.account.username != expected.account.username
        || current
            .agent_access_token
            .as_ref()
            .is_none_or(|token| token.value.as_str() != expected_token)
    {
        return Err("登录状态已更新，请重新打开节点列表".to_string());
    }
    let addresses_changed = current.proxy_addresses != snapshot.proxy_addresses;
    persist_agent_login(
        app,
        &current.account,
        current.account_status,
        &snapshot.proxy_addresses,
        Some(&snapshot.token),
    )?;
    let updated = runtime
        .update_authenticated_session_from_sync(
            &current.account.username,
            expected_token,
            current.account.clone(),
            current.account_status,
            snapshot.proxy_addresses.clone(),
            snapshot.token.clone(),
        )?
        .ok_or_else(|| "登录状态已变化，无法应用节点切换".to_string())?;
    let warning =
        apply_account_defaults_after_sync(app, runtime, &updated.account, addresses_changed);
    runtime.set_permission_sync_error(warning.clone())?;
    if let Ok(state) = agent_auth_state(runtime) {
        let _ = app.emit("agent-auth-state-updated", state);
    }
    warning.map_or(Ok(()), Err)
}

async fn measure_proxy_entry(
    runtime: &AgentRuntime,
    session: &AuthenticatedAgentSession,
    entry: &AgentProxyEntry,
) -> Result<AgentProxyEntrySpeedResult, String> {
    let config_path = current_ui_config_path(runtime)
        .or_else(locate_config_path)
        .ok_or_else(|| "找不到 Agent 配置文件".to_string())?;
    let mut config = desktop_agent_be::config::AgentConfig::load(Path::new(&config_path))
        .map_err(|error| format!("加载测速配置失败：{error}"))?;
    config.username.clone_from(&session.account.username);
    config.private_key_path = session.private_key_path.to_string_lossy().into_owned();
    let addresses = vec![entry.address.clone()];
    let client = AgentClientConfig::new(&config, &addresses, None, None);

    let connect_started = Instant::now();
    let connection = AuthenticatedConnection::connect(&client)
        .await
        .map_err(|error| format!("连接 Proxy Entry 失败：{error}"))?;
    let latency_ms = elapsed_millis(connect_started);
    let download_started = Instant::now();
    let download_bytes = connection
        .download_speed_test(DEFAULT_SPEED_TEST_DOWNLOAD_BYTES)
        .await
        .map_err(|error| format!("Proxy Entry 测速失败：{error}"))?;
    let download_micros = download_started.elapsed().as_micros().max(1);
    let bytes_per_second =
        (u128::from(download_bytes) * 1_000_000 / download_micros).min(u128::from(u64::MAX)) as u64;
    Ok(AgentProxyEntrySpeedResult {
        latency_ms,
        download_bytes,
        download_millis: (download_micros / 1_000).max(1) as u64,
        bytes_per_second,
    })
}

fn elapsed_millis(started: Instant) -> u64 {
    started
        .elapsed()
        .as_millis()
        .max(1)
        .min(u128::from(u64::MAX)) as u64
}
