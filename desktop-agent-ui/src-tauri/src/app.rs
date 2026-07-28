use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::Manager;
use tracing::info;

use crate::agent::{
    apply_ui_log_level, clear_packet_capture_runtime, get_agent_state_inner,
    packet_capture_runtime_status, resolve_agent_output_path, set_packet_capture_runtime_enabled,
    start_agent_command, stop_agent_inner_command,
};
use crate::auth::{authenticate_and_download, registration_page_url, write_managed_private_key};
use crate::config::{
    apply_managed_credentials_to_config, enforce_managed_identity, install_bundled_agent_assets,
    load_config_from_path, load_default_config, locate_config_path, make_absolute_path,
    primary_agent_config_path, proxy_web_url_from_config, redact_managed_identity,
    write_config_file,
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
    AgentAuthState, AgentLoginRequest, AgentState, ConnectivityReport, LoadedAgentConfig,
    NetworkTrafficSnapshot, PacketCaptureRuntimeStatus,
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
    install_and_start_windows_service, run_windows_service, send_service_request,
    INSTALL_SERVICE_ARG, SERVICE_ARG,
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
    let agent_state = get_agent_state_inner(&runtime)?;
    if agent_state.running {
        let stopped = stop_agent_inner_command(&runtime)?;
        if stopped.running {
            return Err("更新登录凭据前无法停止 Agent".to_string());
        }
    }

    let private_key_path = write_managed_private_key(
        &app,
        &downloaded.account.username,
        downloaded.account.key_version,
        &downloaded.private_key_pem,
    )?;
    let loaded = apply_managed_credentials_to_config(
        &config_path,
        &downloaded.account.username,
        &private_key_path,
    )?;
    let ui_config = redact_managed_identity(loaded.clone())?;
    apply_ui_log_level(&runtime, &loaded.summary.log_level);
    remember_ui_config_path(&runtime, &loaded.path)?;

    let account = downloaded.account;
    runtime.set_authenticated_session(
        account.clone(),
        private_key_path,
        downloaded.proxy_web_url,
    )?;
    info!(
        username = %account.username,
        key_version = account.key_version,
        config_path = %loaded.path,
        "Agent 登录凭据已安全下载并应用"
    );
    #[cfg(any(windows, target_os = "macos"))]
    sync_tray_tun_checked(&app, loaded.summary.tun_enabled);

    Ok(AgentAuthState {
        authenticated: true,
        account: Some(account),
        config: Some(ui_config),
    })
}

#[tauri::command]
async fn logout_agent(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentAuthState, String> {
    let runtime = runtime.inner().clone();
    let _operation = runtime.auth_operation.lock().await;
    let state = stop_agent_inner_command(&runtime)?;
    if state.running {
        return Err("Agent 仍在运行，无法安全退出登录".to_string());
    }
    if let Some(session) = runtime.take_authenticated_session()? {
        info!(username = %session.account.username, "Agent 用户已退出登录");
    }
    Ok(AgentAuthState {
        authenticated: false,
        account: None,
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
        current_ui_config_path(runtime)
            .or_else(locate_config_path)
            .map(|path| load_config_from_path(&path))
            .transpose()?
            .map(redact_managed_identity)
            .transpose()?
    } else {
        None
    };
    let account = session.map(|session| session.account);
    Ok(AgentAuthState {
        authenticated: account.is_some(),
        account,
        config,
    })
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
            if let Err(err) = install_and_start_windows_service() {
                eprintln!("{err}");
            }
            return;
        }
        if std::env::args().any(|arg| arg == SERVICE_ARG) {
            if let Err(err) = run_windows_service() {
                eprintln!("{err}");
            }
            return;
        }
    }

    let runtime = Arc::new(AgentRuntime::new());
    runtime.logs.install_tracing();
    let setup_logs = runtime.logs.clone();
    #[cfg(any(windows, target_os = "macos"))]
    let setup_runtime = runtime.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            restore_main_window(app);
        }))
        .setup(move |app| {
            install_bundled_agent_assets(app, &setup_logs).map_err(io::Error::other)?;
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
