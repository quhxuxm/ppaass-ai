use super::*;

const DEFAULT_PERMISSION_SYNC_SECONDS: u64 = 60;

mod managed_config;
use managed_config::*;

pub(crate) fn start_agent_permission_sync(app: tauri::AppHandle, runtime: Arc<AgentRuntime>) {
    tauri::async_runtime::spawn(async move {
        loop {
            sync_agent_permissions_once(&app, &runtime).await;
            let delay = permission_sync_delay(&runtime);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = runtime.permission_sync_notify.notified() => {}
            }
        }
    });
}

pub(crate) async fn sync_agent_permissions_once(
    app: &tauri::AppHandle,
    runtime: &Arc<AgentRuntime>,
) {
    if runtime
        .permission_sync_in_progress
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return;
    }
    let _guard = PermissionSyncGuard(&runtime.permission_sync_in_progress);
    let session = match runtime.authenticated_session() {
        Ok(Some(session)) => session,
        Ok(None) => return,
        Err(error) => {
            record_sync_error(app, runtime, error);
            return;
        }
    };
    let Some(access_token) = session.agent_access_token.as_ref() else {
        record_sync_error(
            app,
            runtime,
            "权限同步凭据缺失，请重新登录以恢复同步".to_string(),
        );
        return;
    };
    let expected_token = access_token.value.clone();
    let snapshot = match fetch_agent_permission_snapshot(
        &session.proxy_web_url,
        expected_token.as_str(),
        &session.account.username,
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(failure) => {
            if failure.credentials_invalid {
                warn!(username = %session.account.username, "Agent 权限同步凭据已失效");
            }
            if failure.proxy_address_not_assigned {
                fail_closed_unassigned_proxy_address(app, runtime, &session).await;
                return;
            }
            record_sync_error(app, runtime, failure.message);
            return;
        }
    };

    let _operation = runtime.auth_operation.lock().await;
    let current = match runtime.authenticated_session() {
        Ok(Some(current))
            if current.account.username == session.account.username
                && current
                    .agent_access_token
                    .as_ref()
                    .is_some_and(|token| token.value.as_str() == expected_token.as_str()) =>
        {
            current
        }
        _ => return,
    };
    let (account, account_status, mut warning) =
        apply_permission_snapshot(&current.account, &snapshot);
    let proxy_addresses_changed = current.proxy_addresses != snapshot.proxy_addresses;
    if let Err(error) = persist_agent_login(
        app,
        &account,
        account_status,
        &snapshot.proxy_addresses,
        Some(&snapshot.token),
    ) {
        record_sync_error(
            app,
            runtime,
            format!("权限已验证但无法持久化，将稍后重试：{error}"),
        );
        return;
    }
    let updated = match runtime.update_authenticated_session_from_sync(
        &session.account.username,
        expected_token.as_str(),
        account,
        account_status,
        snapshot.proxy_addresses.clone(),
        snapshot.token,
    ) {
        Ok(Some(updated)) => updated,
        Ok(None) => return,
        Err(error) => {
            record_sync_error(app, runtime, error);
            return;
        }
    };
    disable_packet_capture_if_revoked(runtime, &updated.account);
    warning = combine_sync_warnings(
        warning,
        apply_account_defaults_after_sync(app, runtime, &updated.account, proxy_addresses_changed),
    );
    let _ = runtime.set_permission_sync_error(warning.clone());
    info!(
        username = %updated.account.username,
        permissions = updated.account.permissions.len(),
        status = ?updated.account_status,
        "Agent 用户权限同步成功"
    );
    emit_auth_state(app, runtime);
    if updated.account_status != AgentAuthAccountStatus::Active {
        let status = match updated.account_status {
            AgentAuthAccountStatus::Active => return,
            AgentAuthAccountStatus::Expired => "user_expired",
            AgentAuthAccountStatus::Disabled => "user_disabled",
        };
        let _ = app.emit("agent-auth-status", status);
    }
}

fn combine_sync_warnings(first: Option<String>, second: Option<String>) -> Option<String> {
    match (first, second) {
        (Some(first), Some(second)) => Some(format!("{first}；{second}")),
        (Some(message), None) | (None, Some(message)) => Some(message),
        (None, None) => None,
    }
}

fn disable_packet_capture_if_revoked(runtime: &AgentRuntime, account: &AgentAuthAccount) {
    if account.has_permission(AGENT_PACKET_CAPTURE_PERMISSION) {
        return;
    }
    let enabled = packet_capture_runtime_status(runtime)
        .map(|status| status.enabled)
        .unwrap_or(false);
    if enabled {
        if let Err(error) = set_packet_capture_runtime_enabled(runtime, false) {
            let message = format!("抓包权限已撤销，但关闭正在运行的抓包失败：{error}");
            warn!("{message}");
            runtime.logs.push(message);
        } else {
            info!(username = %account.username, "抓包权限已撤销，正在运行的抓包已关闭");
        }
    }
}

fn permission_sync_delay(runtime: &AgentRuntime) -> std::time::Duration {
    let seconds = runtime
        .authenticated_session()
        .ok()
        .flatten()
        .and_then(|session| session.agent_access_token)
        .map(|token| token.refresh_after_seconds)
        .unwrap_or(DEFAULT_PERMISSION_SYNC_SECONDS)
        .clamp(60, 3600);
    std::time::Duration::from_secs(seconds)
}

fn record_sync_error(app: &tauri::AppHandle, runtime: &AgentRuntime, message: String) {
    warn!("{message}");
    runtime.logs.push(message.clone());
    let _ = runtime.set_permission_sync_error(Some(message));
    emit_auth_state(app, runtime);
}

fn emit_auth_state(app: &tauri::AppHandle, runtime: &AgentRuntime) {
    if let Ok(state) = agent_auth_state(runtime) {
        let _ = app.emit("agent-auth-state-updated", state);
    }
}

struct PermissionSyncGuard<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for PermissionSyncGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_delay_is_clamped_and_defaults_without_a_session() {
        let runtime = AgentRuntime::new();
        assert_eq!(
            permission_sync_delay(&runtime),
            std::time::Duration::from_secs(DEFAULT_PERMISSION_SYNC_SECONDS)
        );
    }
}
