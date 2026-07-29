use super::*;

pub(crate) fn load_agent_config_inner(
    runtime: &AgentRuntime,
    path: Option<String>,
) -> Result<LoadedAgentConfig, String> {
    let config_path = match path.filter(|value| !value.trim().is_empty()) {
        Some(value) => PathBuf::from(value),
        None => current_ui_config_path(runtime)
            .or_else(locate_config_path)
            .ok_or_else(|| {
                "找不到 agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。"
                    .to_string()
            })?,
    };

    let loaded = load_config_from_path(&config_path)?;
    apply_ui_log_level(runtime, &loaded.summary.log_level);
    remember_ui_config_path(runtime, &loaded.path)?;
    redact_managed_identity(loaded)
}

pub(crate) fn save_agent_config_inner(
    runtime: &AgentRuntime,
    path: String,
    raw: String,
) -> Result<LoadedAgentConfig, String> {
    let session = runtime.require_authenticated_session()?;
    let config_path = make_absolute_path(Path::new(&path));
    let managed_raw = enforce_managed_identity(
        &raw,
        &session.account.username,
        &session.private_key_path,
        &session.proxy_identity_public_key_path,
        &session.proxy_web_url,
    )?;
    write_config_file(&config_path, &managed_raw)?;

    let loaded = if let Some(primary_path) = primary_agent_config_path(&config_path) {
        write_config_file(&primary_path, &managed_raw)?;
        load_config_from_path(&primary_path)?
    } else {
        load_config_from_path(&config_path)?
    };

    apply_ui_log_level(runtime, &loaded.summary.log_level);
    remember_ui_config_path(runtime, &loaded.path)?;
    #[cfg(windows)]
    let _ = send_service_request(&ServiceRequest::SetLogLevel {
        log_level: loaded.summary.log_level.clone(),
    });

    redact_managed_identity(loaded)
}

pub(crate) fn remember_ui_config_path(runtime: &AgentRuntime, path: &str) -> Result<(), String> {
    *runtime
        .ui_config_path
        .lock()
        .map_err(|_| "UI 配置路径状态锁已损坏".to_string())? = Some(PathBuf::from(path));
    Ok(())
}

pub(crate) fn agent_auth_state(runtime: &AgentRuntime) -> Result<AgentAuthState, String> {
    let session = runtime.authenticated_session()?;
    let config = if session.is_some() {
        match current_ui_config_path(runtime).or_else(locate_config_path) {
            Some(path) => match load_config_from_path(&path).and_then(redact_managed_identity) {
                Ok(config) => Some(config),
                Err(error) => {
                    let message =
                        format!("读取 Agent 配置失败，保留当前登录状态并暂不返回配置：{error}");
                    warn!(config_path = %path.display(), "{message}");
                    runtime.logs.push(message);
                    None
                }
            },
            None => {
                let message = "找不到 Agent 配置文件，保留当前登录状态并暂不返回配置".to_string();
                warn!("{message}");
                runtime.logs.push(message);
                None
            }
        }
    } else {
        None
    };
    let account = session.as_ref().map(|session| session.account.clone());
    let account_status = session.map(|session| session.account_status);
    Ok(AgentAuthState {
        authenticated: account.is_some(),
        account,
        account_status,
        config,
    })
}

pub(crate) fn restore_agent_login_on_startup(
    app: &tauri::AppHandle,
    runtime: &Arc<AgentRuntime>,
) -> Result<(), String> {
    let Some(persisted) = load_persisted_agent_login(app)? else {
        return Ok(());
    };
    let config_path = locate_config_path().ok_or_else(|| {
        "持久登录凭据存在，但找不到 Agent 配置文件；将保留凭据并等待下次启动恢复".to_string()
    })?;
    let proxy_web_url = proxy_web_url_from_config(&config_path)?;
    let loaded = apply_managed_credentials_to_config(
        &config_path,
        &persisted.account.username,
        &persisted.private_key_path,
        &persisted.proxy_identity_public_key_path,
    )?;
    apply_ui_log_level(runtime, &loaded.summary.log_level);
    remember_ui_config_path(runtime, &loaded.path)?;
    #[cfg(windows)]
    activate_windows_service_session(app)?;
    runtime.set_authenticated_session(
        persisted.account.clone(),
        persisted.account_status,
        persisted.private_key_path,
        persisted.proxy_identity_public_key_path,
        proxy_web_url,
    )?;
    info!(
        username = %persisted.account.username,
        key_version = persisted.account.key_version,
        "已从本机受管凭据恢复 Agent 长期登录状态"
    );
    Ok(())
}

pub(crate) fn start_verified_proxy_auth_status_listener(
    app: tauri::AppHandle,
    runtime: Arc<AgentRuntime>,
) {
    let mut statuses = common::subscribe_verified_proxy_auth_statuses();
    tauri::async_runtime::spawn(async move {
        loop {
            let status = match statuses.recv().await {
                Ok(status) => status,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            let _operation = runtime.auth_operation.lock().await;
            let current_username = match runtime.authenticated_session() {
                Ok(Some(session)) => session.account.username,
                Ok(None) => continue,
                Err(error) => {
                    runtime
                        .logs
                        .push(format!("读取 Agent 登录状态失败：{error}"));
                    continue;
                }
            };
            let reason = match status {
                common::VerifiedProxyAuthStatus::Active { username }
                    if username == current_username =>
                {
                    Some("active")
                }
                common::VerifiedProxyAuthStatus::UserExpired { username } => {
                    verified_auth_failure_reason(
                        protocol::AuthFailureCode::UserExpired,
                        &username,
                        &current_username,
                    )
                }
                common::VerifiedProxyAuthStatus::UserDisabled { username } => {
                    verified_auth_failure_reason(
                        protocol::AuthFailureCode::UserDisabled,
                        &username,
                        &current_username,
                    )
                }
                _ => None,
            };
            let Some(reason) = reason else {
                continue;
            };
            report_verified_proxy_auth_status(&app, &runtime, &current_username, reason);
        }
    });
}

pub(crate) fn verified_auth_failure_reason(
    code: protocol::AuthFailureCode,
    failure_username: &str,
    current_username: &str,
) -> Option<&'static str> {
    if failure_username != current_username {
        return None;
    }
    match code {
        protocol::AuthFailureCode::UserExpired => Some("user_expired"),
        protocol::AuthFailureCode::UserDisabled => Some("user_disabled"),
        protocol::AuthFailureCode::Other => None,
    }
}

#[cfg(windows)]
pub(crate) fn start_windows_service_auth_failure_listener(
    app: tauri::AppHandle,
    runtime: Arc<AgentRuntime>,
) {
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if !runtime.is_authenticated() {
                continue;
            }
            let service_status =
                match tauri::async_runtime::spawn_blocking(windows_service_auth_status).await {
                    Ok(Ok(status)) => status,
                    // A stopped/upgrading Service, an IPC timeout, and an invalid
                    // local Service session are not authoritative account state.
                    Ok(Err(_)) | Err(_) => continue,
                };
            let Some(service_status) = service_status else {
                continue;
            };
            let _operation = runtime.auth_operation.lock().await;
            let current_username = match runtime.authenticated_session() {
                Ok(Some(session)) => session.account.username,
                Ok(None) | Err(_) => continue,
            };
            if service_status.username != current_username {
                continue;
            }
            let Some(reason) = verified_auth_failure_reason(
                match service_status.status {
                    AgentAuthAccountStatus::Active => {
                        report_verified_proxy_auth_status(
                            &app,
                            &runtime,
                            &current_username,
                            "active",
                        );
                        continue;
                    }
                    AgentAuthAccountStatus::Expired => protocol::AuthFailureCode::UserExpired,
                    AgentAuthAccountStatus::Disabled => protocol::AuthFailureCode::UserDisabled,
                },
                &current_username,
                &current_username,
            ) else {
                continue;
            };
            report_verified_proxy_auth_status(&app, &runtime, &current_username, reason);
        }
    });
}

pub(crate) fn report_verified_proxy_auth_status(
    app: &tauri::AppHandle,
    runtime: &AgentRuntime,
    username: &str,
    reason: &'static str,
) {
    let status = match reason {
        "active" => AgentAuthAccountStatus::Active,
        "user_expired" => AgentAuthAccountStatus::Expired,
        "user_disabled" => AgentAuthAccountStatus::Disabled,
        _ => return,
    };
    let session = match runtime.set_authenticated_account_status(username, status) {
        Ok(Some(session)) => session,
        Ok(None) => return,
        Err(error) => {
            runtime
                .logs
                .push(format!("更新 Proxy 账号状态失败：{error}"));
            return;
        }
    };
    if let Err(error) = persist_agent_login(app, &session.account, status) {
        runtime
            .logs
            .push(format!("保存 Proxy 账号状态失败：{error}"));
    }
    if reason == "active" {
        runtime
            .logs
            .push(format!("Proxy 已确认用户 {username} 的账号状态已恢复"));
    } else {
        runtime.logs.push(format!(
            "Proxy 已确认用户 {username} {}；保留登录状态和本机凭据，Agent 将继续等待账号恢复",
            if reason == "user_expired" {
                "已过期"
            } else {
                "已停用"
            }
        ));
    }
    if let Err(error) = app.emit("agent-auth-status", reason) {
        runtime
            .logs
            .push(format!("通知界面 Proxy 账号状态失败：{error}"));
    }
}

pub(crate) fn current_ui_config_path(runtime: &AgentRuntime) -> Option<PathBuf> {
    runtime
        .ui_config_path
        .lock()
        .ok()
        .and_then(|path| path.clone())
        .or_else(|| {
            runtime
                .config_path
                .lock()
                .ok()
                .and_then(|path| path.clone())
        })
}
