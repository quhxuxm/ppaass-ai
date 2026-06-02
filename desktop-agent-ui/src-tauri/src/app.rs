use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::agent::{
    apply_ui_log_level, get_agent_state_inner, start_agent_command, stop_agent_inner_command,
};
use crate::config::{
    install_bundled_agent_assets, load_config_from_path, locate_config_path, make_absolute_path,
    primary_agent_config_path, write_config_file,
};
use crate::diagnostics::run_connectivity_tests_blocking;
#[cfg(target_os = "macos")]
use crate::macos_helper::{
    check_macos_tun_helper_on_startup, run_macos_tun_helper_service_from_args,
    TUN_HELPER_SERVICE_ARG,
};
#[cfg(windows)]
use crate::models::ServiceRequest;
use crate::models::{AgentState, ConnectivityReport, LoadedAgentConfig, NetworkTrafficSnapshot};
use crate::process_util::run_blocking;
use crate::runtime::AgentRuntime;
use crate::telemetry::{get_dns_resolution_records_inner, get_network_traffic_snapshot_inner};
use crate::tray::restore_main_window;
#[cfg(any(windows, target_os = "macos"))]
use crate::tray::{hide_window_to_tray, hide_window_to_tray_after_minimize, setup_system_tray};
#[cfg(windows)]
use crate::windows_service::{
    install_and_start_windows_service, run_windows_service, send_service_request,
    INSTALL_SERVICE_ARG, SERVICE_ARG,
};

#[tauri::command]
async fn load_agent_config(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    path: Option<String>,
) -> Result<LoadedAgentConfig, String> {
    let runtime = runtime.inner().clone();
    run_blocking("加载配置", move || {
        load_agent_config_inner(&runtime, path)
    })
    .await
}

#[tauri::command]
async fn save_agent_config(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    path: String,
    raw: String,
) -> Result<LoadedAgentConfig, String> {
    let runtime = runtime.inner().clone();
    run_blocking("保存配置", move || {
        save_agent_config_inner(&runtime, path, raw)
    })
    .await
}

#[tauri::command]
async fn get_agent_state(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentState, String> {
    let runtime = runtime.inner().clone();
    run_blocking("读取 Agent 状态", move || {
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
        start_agent_command(&runtime, config_path)
    })
    .await
}

#[tauri::command]
async fn stop_agent(runtime: tauri::State<'_, Arc<AgentRuntime>>) -> Result<AgentState, String> {
    let runtime = runtime.inner().clone();
    run_blocking("停止 Agent", move || stop_agent_inner_command(&runtime)).await
}

#[tauri::command]
async fn run_connectivity_tests(path: Option<String>) -> Result<ConnectivityReport, String> {
    run_blocking("诊断", move || run_connectivity_tests_blocking(path)).await
}

#[tauri::command]
async fn get_network_traffic_snapshot() -> Result<NetworkTrafficSnapshot, String> {
    run_blocking("读取流量", get_network_traffic_snapshot_inner).await
}

#[tauri::command]
async fn get_dns_resolution_records(
) -> Result<Vec<desktop_agent_be::telemetry::DnsResolutionRecord>, String> {
    run_blocking("读取 DNS 解析记录", get_dns_resolution_records_inner).await
}

fn load_agent_config_inner(
    runtime: &AgentRuntime,
    path: Option<String>,
) -> Result<LoadedAgentConfig, String> {
    let config_path = match path.filter(|value| !value.trim().is_empty()) {
        Some(value) => PathBuf::from(value),
        None => locate_config_path().ok_or_else(|| {
            "找不到 agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。".to_string()
        })?,
    };

    let loaded = load_config_from_path(&config_path)?;
    apply_ui_log_level(runtime, &loaded.summary.log_level);
    Ok(loaded)
}

fn save_agent_config_inner(
    runtime: &AgentRuntime,
    path: String,
    raw: String,
) -> Result<LoadedAgentConfig, String> {
    let config_path = make_absolute_path(Path::new(&path));
    write_config_file(&config_path, &raw)?;

    let loaded = if let Some(primary_path) = primary_agent_config_path(&config_path) {
        write_config_file(&primary_path, &raw)?;
        load_config_from_path(&primary_path)?
    } else {
        load_config_from_path(&config_path)?
    };

    apply_ui_log_level(runtime, &loaded.summary.log_level);
    #[cfg(windows)]
    let _ = send_service_request(&ServiceRequest::SetLogLevel {
        log_level: loaded.summary.log_level.clone(),
    });

    Ok(loaded)
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

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            restore_main_window(app);
        }))
        .setup(move |app| {
            install_bundled_agent_assets(app, &setup_logs)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            #[cfg(any(windows, target_os = "macos"))]
            setup_system_tray(app).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
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
            load_agent_config,
            save_agent_config,
            get_agent_state,
            start_agent,
            stop_agent,
            run_connectivity_tests,
            get_network_traffic_snapshot,
            get_dns_resolution_records
        ])
        .run(tauri::generate_context!())
        .expect("error while running PPAASS Desktop Agent UI");
}
