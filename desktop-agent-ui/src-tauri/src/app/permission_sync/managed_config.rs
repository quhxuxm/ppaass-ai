use super::*;

pub(super) async fn fail_closed_unassigned_proxy_address(
    app: &tauri::AppHandle,
    runtime: &Arc<AgentRuntime>,
    expected: &crate::runtime::AuthenticatedAgentSession,
) {
    let _operation = runtime.auth_operation.lock().await;
    let expected_token = expected
        .agent_access_token
        .as_ref()
        .map(|token| token.value.to_string())
        .unwrap_or_default();
    let current = match runtime
        .clear_authenticated_proxy_addresses(&expected.account.username, &expected_token)
    {
        Ok(Some(session)) => session,
        Ok(None) => return,
        Err(error) => {
            record_sync_error(app, runtime, error);
            return;
        }
    };
    let was_running = get_agent_state_inner(runtime)
        .map(|state| state.running)
        .unwrap_or(true);
    if was_running {
        runtime
            .resume_after_proxy_assignment
            .store(true, std::sync::atomic::Ordering::Release);
    }
    let mut failures = Vec::new();
    if let Err(error) = stop_agent_inner_command(runtime) {
        failures.push(format!("停止 Agent 失败：{error}"));
    }
    let should_resume = runtime
        .resume_after_proxy_assignment
        .load(std::sync::atomic::Ordering::Acquire);
    if let Err(error) = persist_unassigned_agent_login(
        app,
        &current.account,
        current.account_status,
        current.agent_access_token.as_ref(),
        should_resume,
    ) {
        failures.push(format!("保存未分配状态失败：{error}"));
    }
    let message = if failures.is_empty() {
        "管理员未分配 Proxy 地址".to_string()
    } else {
        format!("管理员未分配 Proxy 地址；{}", failures.join("；"))
    };
    warn!(username = %current.account.username, "Agent 因未分配 Proxy 地址已进入 fail-closed 状态");
    runtime.logs.push(message.clone());
    let _ = runtime.set_permission_sync_error(Some(message));
    emit_agent_state(app, runtime);
    emit_auth_state(app, runtime);
}

pub(super) fn apply_account_defaults_after_sync(
    app: &tauri::AppHandle,
    runtime: &AgentRuntime,
    account: &AgentAuthAccount,
    proxy_addresses_changed: bool,
) -> Option<String> {
    let (was_running, state_unknown) = match get_agent_state_inner(runtime) {
        Ok(state) => (state.running, false),
        Err(_) => (false, true),
    };
    let resume_pending = runtime
        .resume_after_proxy_assignment
        .load(std::sync::atomic::Ordering::Acquire);
    let should_resume = was_running || resume_pending || (state_unknown && proxy_addresses_changed);

    if proxy_addresses_changed && (was_running || state_unknown) {
        runtime
            .resume_after_proxy_assignment
            .store(should_resume, std::sync::atomic::Ordering::Release);
        if let Err(error) = stop_agent_inner_command(runtime) {
            return Some(format!("Proxy 地址已更新，但停止旧 Agent 失败：{error}"));
        }
        emit_agent_state(app, runtime);
    }

    let path = match current_ui_config_path(runtime).or_else(locate_config_path) {
        Some(path) => path,
        None => {
            return managed_update_failure(
                app,
                runtime,
                should_resume,
                "权限已更新，但找不到 Agent 配置，无法应用受管配置".to_string(),
            )
        }
    };
    let (loaded, applied) = match enforce_managed_config_path_for_account(&path, account) {
        Ok(result) => result,
        Err(error) => {
            return managed_update_failure(
                app,
                runtime,
                should_resume,
                format!("权限已更新，但应用受管默认配置失败：{error}"),
            )
        }
    };
    if !applied.any() && !proxy_addresses_changed && !resume_pending {
        return None;
    }
    apply_ui_log_level(runtime, &loaded.summary.log_level);
    if let Err(error) = remember_trusted_ui_config(runtime, &loaded) {
        return managed_update_failure(
            app,
            runtime,
            should_resume,
            format!("受管配置已写入，但更新配置状态失败：{error}"),
        );
    }
    apply_windows_runtime_default(&loaded, applied);
    log_applied_defaults(account, applied);
    if !should_resume {
        return None;
    }

    runtime
        .resume_after_proxy_assignment
        .store(false, std::sync::atomic::Ordering::Release);
    match restart_agent_after_managed_config_update(runtime, Path::new(&loaded.path), true) {
        Ok(state) if state.running => {
            let _ = app.emit("agent-state-updated", state);
            info!(username = %account.username, "Agent 已自动重启并应用最新受管配置");
            None
        }
        Ok(state) => {
            let _ = app.emit("agent-state-updated", state);
            managed_update_failure(
                app,
                runtime,
                true,
                "受管配置已更新，但 Agent 自动重启后未运行".to_string(),
            )
        }
        Err(error) => managed_update_failure(
            app,
            runtime,
            true,
            format!("受管配置已更新，但 Agent 自动重启失败：{error}"),
        ),
    }
}

fn managed_update_failure(
    app: &tauri::AppHandle,
    runtime: &AgentRuntime,
    should_resume: bool,
    mut message: String,
) -> Option<String> {
    if should_resume {
        runtime
            .resume_after_proxy_assignment
            .store(true, std::sync::atomic::Ordering::Release);
    }
    if let Err(error) = stop_agent_inner_command(runtime) {
        message.push_str(&format!("；再次停止 Agent 失败：{error}"));
    }
    emit_agent_state(app, runtime);
    Some(message)
}

fn emit_agent_state(app: &tauri::AppHandle, runtime: &AgentRuntime) {
    if let Ok(state) = get_agent_state_inner(runtime) {
        let _ = app.emit("agent-state-updated", state);
    }
}

fn log_applied_defaults(
    account: &AgentAuthAccount,
    applied: crate::config::AppliedAccountDefaults,
) {
    info!(
        username = %account.username,
        packet_capture_defaults = applied.packet_capture,
        egress_defaults = applied.egress,
        runtime_defaults = applied.runtime,
        "已按最新 Agent 权限应用内置默认配置"
    );
}

#[cfg(windows)]
fn apply_windows_runtime_default(
    loaded: &LoadedAgentConfig,
    applied: crate::config::AppliedAccountDefaults,
) {
    if applied.runtime {
        let _ = send_service_request(&ServiceRequest::SetLogLevel {
            log_level: loaded.summary.log_level.clone(),
        });
    }
}

#[cfg(not(windows))]
fn apply_windows_runtime_default(
    _loaded: &LoadedAgentConfig,
    _applied: crate::config::AppliedAccountDefaults,
) {
}
