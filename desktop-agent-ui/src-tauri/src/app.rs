use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::{Emitter, Manager};
use tracing::{info, warn};

use crate::agent::{
    apply_ui_log_level, clear_packet_capture_runtime, get_agent_state_inner,
    packet_capture_runtime_status, resolve_agent_output_path, set_packet_capture_runtime_enabled,
    start_agent_command, stop_agent_inner_command,
};
use crate::auth::{
    authenticate_and_download, cleanup_old_managed_private_keys, destroy_managed_private_key,
    destroy_managed_proxy_identity_public_key, destroy_persisted_agent_login,
    load_persisted_agent_login, open_system_browser, persist_agent_login,
    poll_device_authorization, registration_page_url, start_device_authorization,
    write_managed_private_key, write_managed_proxy_identity_public_key, DeviceAuthorizationPoll,
    DownloadedCredential,
};
use crate::config::{
    apply_managed_credentials_to_config, clear_managed_credentials_from_config,
    enforce_managed_identity, install_bundled_agent_assets, load_config_from_path,
    load_default_config, locate_config_path, make_absolute_path, primary_agent_config_path,
    proxy_web_url_from_config, redact_managed_identity, write_config_file,
};
use crate::diagnostics::run_connectivity_tests_blocking;
#[cfg(target_os = "macos")]
use crate::macos_helper::{
    check_macos_tun_helper_on_startup, run_macos_tun_helper_service_from_args,
    TUN_HELPER_SERVICE_ARG,
};
#[cfg(windows)]
use crate::models::ServiceRequest;
use crate::models::{
    AgentAuthAccountStatus, AgentAuthState, AgentDeviceLoginProgress, AgentLoginRequest,
    AgentState, ConnectivityReport, LoadedAgentConfig, NetworkTrafficSnapshot,
    PacketCaptureRuntimeStatus,
};
use crate::packet_capture::{read_packet_capture, PacketCaptureReport};
use crate::process_util::run_blocking;
use crate::runtime::AgentRuntime;
use crate::telemetry::{get_dns_resolution_records_inner, get_network_traffic_snapshot_inner};
use crate::tray::restore_main_window;
#[cfg(any(windows, target_os = "macos"))]
use crate::tray::{
    hide_window_to_tray, hide_window_to_tray_after_minimize, setup_system_tray,
    sync_tray_tun_checked,
};
#[cfg(windows)]
use crate::windows_service::{
    activate_windows_service_session, install_and_start_windows_service,
    invalidate_windows_service_session, run_windows_service, send_service_request,
    service_config_root_from_args, windows_service_auth_status, INSTALL_SERVICE_ARG, SERVICE_ARG,
};

#[tauri::command]
async fn get_agent_auth_state(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentAuthState, String> {
    agent_auth_state(runtime.inner())
}

#[tauri::command]
async fn open_user_registration(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("user-registration") {
        window
            .show()
            .and_then(|_| window.unminimize())
            .and_then(|_| window.set_focus())
            .map_err(|_| "无法显示新用户注册窗口".to_string())?;
        return Ok(());
    }

    let config_path = current_ui_config_path(runtime.inner())
        .or_else(locate_config_path)
        .ok_or_else(|| {
            "找不到 Agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。".to_string()
        })?;
    let proxy_web_url = proxy_web_url_from_config(&config_path)?;
    let registration_url = registration_page_url(&proxy_web_url)
        .map_err(|_| "Agent 注册服务配置无效，请联系管理员".to_string())?;

    tauri::WebviewWindowBuilder::new(
        &app,
        "user-registration",
        tauri::WebviewUrl::External(registration_url),
    )
    .title("PPAASS 新用户注册")
    .inner_size(1040.0, 760.0)
    .min_inner_size(760.0, 600.0)
    .center()
    .incognito(true)
    .on_navigation(|url| matches!(url.scheme(), "http" | "https"))
    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
    .build()
    .map_err(|_| "无法打开新用户注册窗口".to_string())?;

    info!("已打开新用户注册窗口");
    Ok(())
}

#[tauri::command]
async fn login_and_provision_agent(
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
async fn start_agent_device_login(
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
async fn poll_agent_device_login(
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
                downloaded,
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
async fn cancel_agent_device_login(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<(), String> {
    runtime.cancel_pending_device_authorization()?;
    info!("已取消 Windows Agent 浏览器设备登录");
    Ok(())
}

fn device_login_progress(
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

fn provision_downloaded_credential(
    app: &tauri::AppHandle,
    runtime: &Arc<AgentRuntime>,
    config_path: &Path,
    downloaded: DownloadedCredential,
) -> Result<AgentAuthState, String> {
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
    let ui_config = match redact_managed_identity(loaded.clone()) {
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
    if let Err(error) = remember_ui_config_path(runtime, &loaded.path) {
        rollback_downloaded_credential(
            app,
            config_path,
            &private_key_path,
            &proxy_identity_public_key_path,
        );
        return Err(error);
    }

    let account = downloaded.account;
    if let Err(error) = persist_agent_login(app, &account, AgentAuthAccountStatus::Active) {
        rollback_downloaded_credential(
            app,
            config_path,
            &private_key_path,
            &proxy_identity_public_key_path,
        );
        return Err(error);
    }
    if let Err(error) = runtime.set_authenticated_session(
        account.clone(),
        AgentAuthAccountStatus::Active,
        private_key_path.clone(),
        proxy_identity_public_key_path.clone(),
        downloaded.proxy_web_url,
    ) {
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
        config: Some(ui_config),
    })
}

fn rollback_downloaded_credential(
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
async fn logout_agent(
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
        config: None,
    })
}

#[tauri::command]
async fn load_agent_config(
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
async fn save_agent_config(
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
async fn load_default_agent_config(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    path: Option<String>,
) -> Result<LoadedAgentConfig, String> {
    let runtime = runtime.inner().clone();
    run_blocking("加载默认配置", move || {
        runtime.require_authenticated()?;
        redact_managed_identity(load_default_config(&app, path.as_deref())?)
    })
    .await
}

#[tauri::command]
async fn get_agent_state(
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
async fn start_agent(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    config_path: String,
) -> Result<AgentState, String> {
    let runtime = runtime.inner().clone();
    run_blocking("启动 Agent", move || {
        let session = runtime.require_authenticated_session()?;
        let config_path = current_ui_config_path(&runtime)
            .unwrap_or_else(|| make_absolute_path(Path::new(&config_path)));
        let loaded = apply_managed_credentials_to_config(
            &config_path,
            &session.account.username,
            &session.private_key_path,
            &session.proxy_identity_public_key_path,
        )?;
        remember_ui_config_path(&runtime, &loaded.path)?;
        start_agent_command(&runtime, loaded.path)
    })
    .await
}

#[tauri::command]
async fn stop_agent(runtime: tauri::State<'_, Arc<AgentRuntime>>) -> Result<AgentState, String> {
    let runtime = runtime.inner().clone();
    run_blocking("停止 Agent", move || stop_agent_inner_command(&runtime)).await
}

#[tauri::command]
async fn run_connectivity_tests(
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
async fn get_network_traffic_snapshot(
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
async fn get_dns_resolution_records(
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
async fn get_packet_capture(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    config_path: Option<String>,
    limit: Option<usize>,
) -> Result<PacketCaptureReport, String> {
    let runtime = runtime.inner().clone();
    run_blocking("读取抓包结果", move || {
        runtime.require_authenticated()?;
        let config_path = match config_path.filter(|value| !value.trim().is_empty()) {
            Some(value) => PathBuf::from(value),
            None => locate_config_path().ok_or_else(|| "找不到 Agent 配置文件".to_string())?,
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
async fn get_packet_capture_runtime_status(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<PacketCaptureRuntimeStatus, String> {
    let runtime = runtime.inner().clone();
    run_blocking("读取抓包运行状态", move || {
        runtime.require_authenticated()?;
        packet_capture_runtime_status(&runtime)
    })
    .await
}

#[tauri::command]
async fn set_packet_capture_enabled(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    enabled: bool,
) -> Result<PacketCaptureRuntimeStatus, String> {
    let runtime = runtime.inner().clone();
    run_blocking("切换抓包运行状态", move || {
        runtime.require_authenticated()?;
        set_packet_capture_runtime_enabled(&runtime, enabled)
    })
    .await
}

#[tauri::command]
async fn clear_packet_capture(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    config_path: Option<String>,
) -> Result<PacketCaptureRuntimeStatus, String> {
    let runtime = runtime.inner().clone();
    run_blocking("清空抓包文件", move || {
        runtime.require_authenticated()?;
        clear_packet_capture_runtime(&runtime, config_path)
    })
    .await
}

fn load_agent_config_inner(
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

fn save_agent_config_inner(
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

fn remember_ui_config_path(runtime: &AgentRuntime, path: &str) -> Result<(), String> {
    *runtime
        .ui_config_path
        .lock()
        .map_err(|_| "UI 配置路径状态锁已损坏".to_string())? = Some(PathBuf::from(path));
    Ok(())
}

fn agent_auth_state(runtime: &AgentRuntime) -> Result<AgentAuthState, String> {
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

fn restore_agent_login_on_startup(
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

fn start_verified_proxy_auth_status_listener(app: tauri::AppHandle, runtime: Arc<AgentRuntime>) {
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

fn verified_auth_failure_reason(
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
fn start_windows_service_auth_failure_listener(app: tauri::AppHandle, runtime: Arc<AgentRuntime>) {
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

fn report_verified_proxy_auth_status(
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

fn current_ui_config_path(runtime: &AgentRuntime) -> Option<PathBuf> {
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

pub(crate) fn run() {
    #[cfg(target_os = "macos")]
    {
        if std::env::args().any(|arg| arg == TUN_HELPER_SERVICE_ARG) {
            if let Err(err) = run_macos_tun_helper_service_from_args() {
                eprintln!("{err}");
                std::process::exit(1);
            }
            return;
        }
    }

    #[cfg(windows)]
    {
        if std::env::args().any(|arg| arg == INSTALL_SERVICE_ARG) {
            if let Err(err) =
                service_config_root_from_args().and_then(install_and_start_windows_service)
            {
                eprintln!("{err}");
                std::process::exit(1);
            }
            return;
        }
        if std::env::args().any(|arg| arg == SERVICE_ARG) {
            if let Err(err) = service_config_root_from_args().and_then(run_windows_service) {
                eprintln!("{err}");
                std::process::exit(1);
            }
            return;
        }
    }

    let runtime = Arc::new(AgentRuntime::new());
    runtime.logs.install_tracing();
    let setup_logs = runtime.logs.clone();
    let setup_runtime = runtime.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            restore_main_window(app);
        }))
        .setup(move |app| {
            install_bundled_agent_assets(app, &setup_logs).map_err(io::Error::other)?;
            if let Err(error) = restore_agent_login_on_startup(app.handle(), &setup_runtime) {
                setup_logs.push(format!("恢复 Agent 长期登录状态失败：{error}"));
            }
            start_verified_proxy_auth_status_listener(app.handle().clone(), setup_runtime.clone());
            #[cfg(windows)]
            start_windows_service_auth_failure_listener(
                app.handle().clone(),
                setup_runtime.clone(),
            );
            #[cfg(any(windows, target_os = "macos"))]
            setup_system_tray(app, setup_runtime.clone()).map_err(io::Error::other)?;
            #[cfg(target_os = "macos")]
            check_macos_tun_helper_on_startup(&setup_logs);
            Ok(())
        })
        .on_window_event(|window, event| {
            #[cfg(not(any(windows, target_os = "macos")))]
            let _ = (window, event);
            #[cfg(any(windows, target_os = "macos"))]
            if window.label() == "main"
                && matches!(
                    event,
                    tauri::WindowEvent::Resized(_) | tauri::WindowEvent::Focused(false)
                )
            {
                hide_window_to_tray_after_minimize(window.clone());
            }
            #[cfg(any(windows, target_os = "macos"))]
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    hide_window_to_tray(window);
                }
            }
        })
        .manage(runtime)
        .invoke_handler(tauri::generate_handler![
            get_agent_auth_state,
            open_user_registration,
            login_and_provision_agent,
            start_agent_device_login,
            poll_agent_device_login,
            cancel_agent_device_login,
            logout_agent,
            load_agent_config,
            save_agent_config,
            load_default_agent_config,
            get_agent_state,
            start_agent,
            stop_agent,
            run_connectivity_tests,
            get_network_traffic_snapshot,
            get_dns_resolution_records,
            get_packet_capture,
            get_packet_capture_runtime_status,
            set_packet_capture_enabled,
            clear_packet_capture,
        ])
        .run(tauri::generate_context!())
        .expect("error while running PPAASS Desktop Agent UI");
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;

    use super::{agent_auth_state, verified_auth_failure_reason};
    use crate::models::{AgentAuthAccount, AgentAuthAccountStatus};
    use crate::runtime::AgentRuntime;
    use protocol::AuthFailureCode;

    #[test]
    fn only_matching_verified_terminal_proxy_states_are_reported() {
        assert_eq!(
            verified_auth_failure_reason(AuthFailureCode::UserExpired, "alice", "alice"),
            Some("user_expired")
        );
        assert_eq!(
            verified_auth_failure_reason(AuthFailureCode::UserDisabled, "alice", "alice"),
            Some("user_disabled")
        );
        assert_eq!(
            verified_auth_failure_reason(AuthFailureCode::Other, "alice", "alice"),
            None
        );
        assert_eq!(
            verified_auth_failure_reason(AuthFailureCode::UserExpired, "old-user", "new-user"),
            None
        );
    }

    #[test]
    fn auth_state_keeps_session_when_config_cannot_be_loaded() {
        let runtime = AgentRuntime::new();
        runtime
            .set_authenticated_session(
                AgentAuthAccount {
                    username: "alice".to_string(),
                    key_version: 7,
                    expires_at: Some(1_900_000_000),
                },
                AgentAuthAccountStatus::Expired,
                PathBuf::from("managed/alice.pem"),
                PathBuf::from("managed/proxy.pem"),
                "https://proxy.example.com".to_string(),
            )
            .unwrap();
        *runtime.ui_config_path.lock().unwrap() =
            Some(PathBuf::from("/definitely/missing/agent.toml"));

        let state = agent_auth_state(&runtime).unwrap();

        assert!(state.authenticated);
        assert_eq!(state.account.unwrap().username, "alice");
        assert_eq!(state.account_status, Some(AgentAuthAccountStatus::Expired));
        assert!(state.config.is_none());
        assert!(runtime
            .logs
            .snapshot()
            .iter()
            .any(|line| line.contains("保留当前登录状态")));
    }

    #[test]
    fn auth_state_keeps_session_when_config_cannot_be_parsed() {
        let mut invalid_config = tempfile::NamedTempFile::new().unwrap();
        invalid_config
            .write_all(b"this is not = valid [toml")
            .unwrap();
        let runtime = AgentRuntime::new();
        runtime
            .set_authenticated_session(
                AgentAuthAccount {
                    username: "bob".to_string(),
                    key_version: 2,
                    expires_at: None,
                },
                AgentAuthAccountStatus::Active,
                PathBuf::from("managed/bob.pem"),
                PathBuf::from("managed/proxy.pem"),
                "https://proxy.example.com".to_string(),
            )
            .unwrap();
        *runtime.ui_config_path.lock().unwrap() = Some(invalid_config.path().to_path_buf());

        let state = agent_auth_state(&runtime).unwrap();

        assert!(state.authenticated);
        assert_eq!(state.account.unwrap().username, "bob");
        assert_eq!(state.account_status, Some(AgentAuthAccountStatus::Active));
        assert!(state.config.is_none());
    }
}
