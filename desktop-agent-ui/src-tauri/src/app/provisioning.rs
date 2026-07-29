use super::*;

pub(crate) fn provision_downloaded_credential(
    app: &tauri::AppHandle,
    runtime: &Arc<AgentRuntime>,
    config_path: &Path,
    downloaded: DownloadedCredential,
) -> Result<AgentAuthState, String> {
    let agent_access_token = downloaded.agent_access_token.clone().or_else(|| {
        runtime
            .authenticated_session()
            .ok()
            .flatten()
            .and_then(|session| session.agent_access_token)
    });
    let candidate = load_config_from_path(config_path)?;
    validate_config_candidate_against_trusted_baseline(runtime, &downloaded.account, &candidate)?;
    #[cfg(windows)]
    activate_windows_service_session(app)?;
    let agent_state = match get_agent_state_inner(runtime) {
        Ok(state) => state,
        Err(error) => {
            #[cfg(windows)]
            let _ = invalidate_windows_service_session(app);
            return Err(error);
        }
    };
    if agent_state.running {
        let stopped = match stop_agent_inner_command(runtime) {
            Ok(stopped) => stopped,
            Err(error) => {
                #[cfg(windows)]
                let _ = invalidate_windows_service_session(app);
                return Err(error);
            }
        };
        if stopped.running {
            #[cfg(windows)]
            let _ = invalidate_windows_service_session(app);
            return Err("更新登录凭据前无法停止 Agent".to_string());
        }
    }

    let private_key_path = match write_managed_private_key(
        app,
        &downloaded.account.username,
        downloaded.account.key_version,
        &downloaded.private_key_pem,
    ) {
        Ok(path) => path,
        Err(error) => {
            #[cfg(windows)]
            let _ = invalidate_windows_service_session(app);
            return Err(error);
        }
    };
    let proxy_identity_public_key_path = match write_managed_proxy_identity_public_key(
        app,
        &downloaded.proxy_identity_public_key_pem,
    ) {
        Ok(path) => path,
        Err(error) => {
            let _ = destroy_managed_private_key(&private_key_path);
            #[cfg(windows)]
            let _ = invalidate_windows_service_session(app);
            return Err(error);
        }
    };
    let loaded = match apply_managed_credentials_to_config(
        config_path,
        &downloaded.account.username,
        &private_key_path,
        &proxy_identity_public_key_path,
    ) {
        Ok(loaded) => loaded,
        Err(error) => {
            rollback_downloaded_credential(
                app,
                config_path,
                &private_key_path,
                &proxy_identity_public_key_path,
            );
            return Err(error);
        }
    };
    let ui_config = match prepare_config_for_account(loaded.clone(), &downloaded.account) {
        Ok(config) => config,
        Err(error) => {
            rollback_downloaded_credential(
                app,
                config_path,
                &private_key_path,
                &proxy_identity_public_key_path,
            );
            return Err(error);
        }
    };
    apply_ui_log_level(runtime, &loaded.summary.log_level);
    if let Err(error) = remember_trusted_ui_config(runtime, &loaded) {
        rollback_downloaded_credential(
            app,
            config_path,
            &private_key_path,
            &proxy_identity_public_key_path,
        );
        return Err(error);
    }

    let account = downloaded.account;
    if let Err(error) = persist_agent_login(
        app,
        &account,
        AgentAuthAccountStatus::Active,
        agent_access_token.as_ref(),
    ) {
        rollback_downloaded_credential(
            app,
            config_path,
            &private_key_path,
            &proxy_identity_public_key_path,
        );
        return Err(error);
    }
    if let Err(error) = runtime.set_authenticated_session(AuthenticatedAgentSession::new(
        account.clone(),
        AgentAuthAccountStatus::Active,
        private_key_path.clone(),
        proxy_identity_public_key_path.clone(),
        downloaded.proxy_web_url,
        agent_access_token,
        AgentPermissionTrust::ServerVerified,
    )) {
        rollback_downloaded_credential(
            app,
            config_path,
            &private_key_path,
            &proxy_identity_public_key_path,
        );
        return Err(error);
    }
    cleanup_old_managed_private_keys(&private_key_path);
    info!(
        username = %account.username,
        key_version = account.key_version,
        config_path = %loaded.path,
        "Agent 登录凭据已安全下载并应用"
    );
    #[cfg(any(windows, target_os = "macos"))]
    sync_tray_tun_checked(app, loaded.summary.tun_enabled);

    Ok(AgentAuthState {
        authenticated: true,
        account: Some(account),
        account_status: Some(AgentAuthAccountStatus::Active),
        permission_sync_error: None,
        config: Some(ui_config),
    })
}

pub(crate) fn rollback_downloaded_credential(
    app: &tauri::AppHandle,
    config_path: &Path,
    private_key_path: &Path,
    proxy_identity_public_key_path: &Path,
) {
    let _ = destroy_persisted_agent_login(app);
    let _ = clear_managed_credentials_from_config(config_path);
    let _ = destroy_managed_private_key(private_key_path);
    let _ = destroy_managed_proxy_identity_public_key(proxy_identity_public_key_path);
    #[cfg(windows)]
    let _ = invalidate_windows_service_session(app);
    #[cfg(not(windows))]
    let _ = app;
}

#[tauri::command]
pub(crate) async fn logout_agent(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentAuthState, String> {
    #[cfg(not(windows))]
    let _ = &app;
    let runtime = runtime.inner().clone();
    let _operation = runtime.auth_operation.lock().await;
    let state = stop_agent_inner_command(&runtime)?;
    if state.running {
        return Err("Agent 仍在运行，无法安全退出登录".to_string());
    }
    let session = runtime.require_authenticated_session()?;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = destroy_managed_private_key(&session.private_key_path) {
        cleanup_errors.push(error);
    }
    if let Err(error) =
        destroy_managed_proxy_identity_public_key(&session.proxy_identity_public_key_path)
    {
        cleanup_errors.push(error);
    }
    if let Some(config_path) = current_ui_config_path(&runtime).or_else(locate_config_path) {
        if let Err(error) = clear_managed_credentials_from_config(&config_path) {
            cleanup_errors.push(error);
        }
    }
    if let Err(error) = destroy_persisted_agent_login(&app) {
        cleanup_errors.push(error);
    }
    #[cfg(windows)]
    if let Err(error) = invalidate_windows_service_session(&app) {
        cleanup_errors.push(error);
    }
    if !cleanup_errors.is_empty() {
        return Err(format!(
            "Agent 已停止，但清理登录凭据失败：{}",
            cleanup_errors.join("；")
        ));
    }
    if let Some(session) = runtime.take_authenticated_session()? {
        info!(username = %session.account.username, "Agent 用户已退出登录");
    }
    Ok(AgentAuthState {
        authenticated: false,
        account: None,
        account_status: None,
        permission_sync_error: None,
        config: None,
    })
}
