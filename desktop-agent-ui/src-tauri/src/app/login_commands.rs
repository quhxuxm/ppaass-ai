use super::*;

#[tauri::command]
pub(crate) async fn get_agent_auth_state(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentAuthState, String> {
    agent_auth_state(runtime.inner())
}

#[tauri::command]
pub(crate) async fn open_user_account_management(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<(), String> {
    let runtime = runtime.inner().clone();
    let _operation = runtime.auth_operation.lock().await;
    let account_management_url = match runtime.authenticated_session()? {
        Some(session) => {
            let access_token = session
                .agent_access_token
                .as_ref()
                .ok_or_else(|| "当前 Agent 登录缺少账户交接凭据，请重新登录".to_string())?;
            request_account_management_handoff(&session.proxy_web_url, access_token.value.as_str())
                .await?
        }
        None => {
            let config_path = current_ui_config_path(&runtime)
                .or_else(locate_config_path)
                .ok_or_else(|| {
                    "找不到 Agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。"
                        .to_string()
                })?;
            let proxy_web_url = proxy_web_url_from_config(&config_path)?;
            account_management_page_url(&proxy_web_url)
                .map_err(|_| "Agent 账户服务配置无效，请联系管理员".to_string())?
        }
    };
    rebuild_account_management_window(&app, account_management_url)?;
    info!("已打开注册和账户管理窗口");
    Ok(())
}

fn rebuild_account_management_window(
    app: &tauri::AppHandle,
    account_management_url: url::Url,
) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("user-account-management") {
        window
            .destroy()
            .map_err(|_| "无法重建注册和账户管理窗口".to_string())?;
    }
    let account_management_origin = account_management_url.origin();

    tauri::WebviewWindowBuilder::new(
        app,
        "user-account-management",
        tauri::WebviewUrl::External(account_management_url),
    )
    .title("PPAASS 注册和账户管理")
    .inner_size(1040.0, 760.0)
    .min_inner_size(760.0, 600.0)
    .center()
    .incognito(true)
    .on_navigation(move |url| url.origin() == account_management_origin)
    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
    .build()
    .map_err(|_| "无法打开注册和账户管理窗口".to_string())?;
    Ok(())
}

#[tauri::command]
pub(crate) async fn login_and_provision_agent(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    request: AgentLoginRequest,
) -> Result<AgentAuthState, String> {
    let runtime = runtime.inner().clone();
    let _operation = runtime.auth_operation.lock().await;
    if runtime.is_authenticated() {
        return Err("当前 Agent 已经登录，请先退出当前账号".to_string());
    }
    runtime.cancel_pending_device_authorization()?;
    let AgentLoginRequest { username, password } = request;
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("请输入用户名".to_string());
    }
    let password = zeroize::Zeroizing::new(password);
    if password.len() < 8 {
        return Err("密码至少需要 8 位".to_string());
    }
    let config_path = current_ui_config_path(&runtime)
        .or_else(locate_config_path)
        .ok_or_else(|| {
            "找不到 Agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。".to_string()
        })?;
    let proxy_web_url = proxy_web_url_from_config(&config_path)?;
    let downloaded =
        authenticate_and_download(&proxy_web_url, &username, password.as_str()).await?;
    provision_downloaded_credential(&app, &runtime, &config_path, downloaded)
}

#[tauri::command]
pub(crate) async fn rotate_agent_key(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    request: AgentKeyRotationRequest,
) -> Result<AgentAuthState, String> {
    let AgentKeyRotationRequest { password, reason } = request;
    let password = zeroize::Zeroizing::new(password);
    if password.len() < 8 {
        return Err("请输入当前密码".to_string());
    }
    let runtime = runtime.inner().clone();
    let _operation = runtime.auth_operation.lock().await;
    let session = runtime.require_authenticated_session()?;
    if session.account_status != AgentAuthAccountStatus::Active {
        return Err("当前账号不可轮换密钥，请到账户管理提交申请并等待管理员批准".to_string());
    }
    if !session
        .account
        .permissions
        .iter()
        .any(|permission| permission == "key.rotate")
    {
        return Err("当前账号没有轮换密钥的权限".to_string());
    }
    let audit_reason = reason
        .as_deref()
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty());
    if session.account.role == "admin" && audit_reason.is_none() {
        return Err("管理员重新生成密钥必须填写操作原因".to_string());
    }
    if audit_reason.is_some_and(|candidate| candidate.chars().count() > 500) {
        return Err("操作原因不能超过 500 个字符".to_string());
    }

    let config_path = current_ui_config_path(&runtime)
        .or_else(locate_config_path)
        .ok_or_else(|| {
            "找不到 Agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。".to_string()
        })?;
    let proxy_web_url = proxy_web_url_from_config(&config_path)?;
    let was_running = get_agent_state_inner(&runtime)?.running;
    let downloaded = authenticate_rotate_and_download(
        &proxy_web_url,
        &session.account.username,
        password.as_str(),
        audit_reason,
    )
    .await?;
    if downloaded.account.username != session.account.username
        || downloaded.account.role != session.account.role
    {
        return Err("Proxy Web 返回的轮换账号与当前 Agent 登录账号不一致".to_string());
    }

    let state = provision_downloaded_credential(&app, &runtime, &config_path, downloaded)?;
    if was_running {
        let applied_config_path = state
            .config
            .as_ref()
            .map(|config| config.path.clone())
            .ok_or_else(|| "新密钥已应用，但无法确定 Agent 重启配置".to_string())?;
        let restarted = start_agent_command(&runtime, applied_config_path)
            .map_err(|error| format!("新密钥已应用，但 Agent 自动重启失败：{error}"))?;
        if !restarted.running {
            return Err("新密钥已应用，但 Agent 自动重启后未保持运行".to_string());
        }
    }
    info!(
        username = %session.account.username,
        was_running,
        "Agent 已应用用户轮换后的密钥"
    );
    Ok(state)
}

#[tauri::command]
pub(crate) async fn start_agent_device_login(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentDeviceLoginProgress, String> {
    let runtime = runtime.inner().clone();
    let _operation = runtime.auth_operation.lock().await;
    if runtime.is_authenticated() {
        return Err("当前 Agent 已经登录".to_string());
    }
    runtime.cancel_pending_device_authorization()?;
    let config_path = current_ui_config_path(&runtime)
        .or_else(locate_config_path)
        .ok_or_else(|| {
            "找不到 Agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。".to_string()
        })?;
    let proxy_web_url = proxy_web_url_from_config(&config_path)?;
    let started = start_device_authorization(&proxy_web_url).await?;
    let verification_url = started.verification_url.clone();
    let challenge = runtime.set_pending_device_authorization(
        started.device_code,
        started.proxy_web_url,
        config_path,
        started.user_code,
        started.expires_at,
        started.interval_seconds,
    )?;
    if let Err(error) = open_system_browser(&verification_url) {
        let _ = runtime.take_pending_device_authorization_if(challenge.id);
        return Err(error);
    }
    info!(
        expires_at = challenge.expires_at,
        "已在系统默认浏览器中打开 Windows Agent 设备登录"
    );
    Ok(device_login_progress(
        &challenge,
        "authorization_pending",
        challenge.interval_seconds,
        None,
    ))
}

#[tauri::command]
pub(crate) async fn poll_agent_device_login(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentDeviceLoginProgress, String> {
    let runtime = runtime.inner().clone();
    let _operation = runtime.auth_operation.lock().await;
    if runtime.is_authenticated() {
        return Err("当前 Agent 已经登录".to_string());
    }
    let challenge = runtime
        .pending_device_authorization()?
        .ok_or_else(|| "设备登录已取消或失效".to_string())?;
    let poll = match poll_device_authorization(
        &challenge.proxy_web_url,
        &challenge.device_code,
        challenge.interval_seconds,
    )
    .await
    {
        Ok(poll) => poll,
        Err(error) => {
            let _ = runtime.take_pending_device_authorization_if(challenge.id);
            return Err(error);
        }
    };
    match poll {
        DeviceAuthorizationPoll::Pending {
            slow_down,
            retry_after_seconds,
        } => {
            let still_pending = runtime
                .pending_device_authorization()?
                .is_some_and(|pending| pending.id == challenge.id);
            if !still_pending {
                return Err("设备登录已取消".to_string());
            }
            Ok(device_login_progress(
                &challenge,
                if slow_down {
                    "slow_down"
                } else {
                    "authorization_pending"
                },
                retry_after_seconds,
                None,
            ))
        }
        DeviceAuthorizationPoll::Authorized(downloaded) => {
            if !runtime.take_pending_device_authorization_if(challenge.id)? {
                return Err("设备登录已取消".to_string());
            }
            let auth_state = provision_downloaded_credential(
                &app,
                &runtime,
                &challenge.config_path,
                *downloaded,
            )?;
            Ok(device_login_progress(
                &challenge,
                "authenticated",
                0,
                Some(auth_state),
            ))
        }
    }
}

#[tauri::command]
pub(crate) async fn cancel_agent_device_login(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<(), String> {
    runtime.cancel_pending_device_authorization()?;
    info!("已取消 Windows Agent 浏览器设备登录");
    Ok(())
}

pub(crate) fn device_login_progress(
    challenge: &crate::runtime::PendingAgentDeviceAuthorization,
    status: &str,
    retry_after_seconds: u32,
    auth_state: Option<AgentAuthState>,
) -> AgentDeviceLoginProgress {
    AgentDeviceLoginProgress {
        status: status.to_string(),
        user_code: challenge.user_code.clone(),
        expires_at: challenge.expires_at,
        retry_after_seconds,
        auth_state,
    }
}
