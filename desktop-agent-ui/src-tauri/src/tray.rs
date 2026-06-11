#[cfg(any(windows, target_os = "macos"))]
use serde::Serialize;
#[cfg(any(windows, target_os = "macos"))]
use std::path::{Path, PathBuf};
#[cfg(any(windows, target_os = "macos"))]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};
#[cfg(any(windows, target_os = "macos"))]
use std::time::Duration;
#[cfg(any(windows, target_os = "macos"))]
use tauri::Emitter;
use tauri::Manager;

#[cfg(any(windows, target_os = "macos"))]
use crate::agent::{get_agent_state_inner, start_agent_command, stop_agent_inner_command};
#[cfg(any(windows, target_os = "macos"))]
use crate::config::{load_config_from_path, locate_config_path, toggle_tun_enabled_in_config};
#[cfg(any(windows, target_os = "macos"))]
use crate::runtime::AgentRuntime;

#[cfg(any(windows, target_os = "macos"))]
const TRAY_ID: &str = "main";
#[cfg(any(windows, target_os = "macos"))]
const TRAY_SHOW_ID: &str = "show";
#[cfg(any(windows, target_os = "macos"))]
const TRAY_TUN_ID: &str = "tun-enabled";
#[cfg(any(windows, target_os = "macos"))]
const TRAY_EXIT_ID: &str = "exit";
#[cfg(any(windows, target_os = "macos"))]
const TRAY_ICON_BYTES: &[u8] = include_bytes!("../icons/32x32.png");

#[cfg(any(windows, target_os = "macos"))]
static TRAY_TUN_ITEM: OnceLock<tauri::menu::CheckMenuItem<tauri::Wry>> = OnceLock::new();
#[cfg(any(windows, target_os = "macos"))]
static TRAY_TUN_TOGGLE_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn setup_system_tray(
    app: &tauri::App,
    runtime: Arc<AgentRuntime>,
) -> Result<(), String> {
    let icon = tauri::image::Image::from_bytes(TRAY_ICON_BYTES)
        .map(|icon| icon.to_owned())
        .map_err(|err| format!("加载应用托盘图标失败：{err}"))?;
    let tun_item = tauri::menu::CheckMenuItem::with_id(
        app,
        TRAY_TUN_ID,
        "启用 TUN 模式",
        true,
        initial_tun_enabled(),
        None::<&str>,
    )
    .map_err(|err| format!("创建 TUN 托盘菜单失败：{err}"))?;
    let _ = TRAY_TUN_ITEM.set(tun_item.clone());
    let menu = tauri::menu::MenuBuilder::new(app)
        .text(TRAY_SHOW_ID, "显示")
        .item(&tun_item)
        .separator()
        .text(TRAY_EXIT_ID, "退出")
        .build()
        .map_err(|err| format!("创建系统托盘菜单失败：{err}"))?;

    let tun_item_for_event = tun_item.clone();
    let runtime_for_event = runtime.clone();
    let tray_builder = tauri::tray::TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .tooltip("PPAASS Desktop Agent")
        .menu(&menu)
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_menu_event(move |app, event| match event.id().as_ref() {
            TRAY_SHOW_ID => restore_main_window(app),
            TRAY_TUN_ID => {
                handle_tun_menu_event(app, &tun_item_for_event, runtime_for_event.clone())
            }
            TRAY_EXIT_ID => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if cfg!(target_os = "macos") {
                return;
            }
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                button_state: tauri::tray::MouseButtonState::Up,
                ..
            } = event
            {
                restore_main_window(tray.app_handle());
            }
        });

    tray_builder
        .build(app)
        .map_err(|err| format!("创建系统托盘失败：{err}"))?;

    Ok(())
}

#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn sync_tray_tun_checked(app: &tauri::AppHandle, enabled: bool) {
    if app.tray_by_id(TRAY_ID).is_some() {
        if let Some(item) = TRAY_TUN_ITEM.get() {
            let _ = item.set_checked(enabled);
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn initial_tun_enabled() -> bool {
    tun_enabled_for_path(None)
}

#[cfg(any(windows, target_os = "macos"))]
fn tun_enabled_for_path(path: Option<&Path>) -> bool {
    let config_path = path.map(Path::to_path_buf).or_else(locate_config_path);
    config_path
        .and_then(|path| load_config_from_path(&path).ok())
        .map(|config| config.summary.tun_enabled)
        .unwrap_or(false)
}

#[cfg(any(windows, target_os = "macos"))]
fn handle_tun_menu_event(
    app: &tauri::AppHandle,
    item: &tauri::menu::CheckMenuItem<tauri::Wry>,
    runtime: Arc<AgentRuntime>,
) {
    if TRAY_TUN_TOGGLE_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        let config_path = current_ui_config_path(&runtime);
        let _ = item.set_checked(tun_enabled_for_path(config_path.as_deref()));
        emit_to_main(app, "agent-tray-error", "TUN 模式正在切换，请稍候");
        return;
    }

    let app = app.clone();
    let item = item.clone();
    let config_path = current_ui_config_path(&runtime);

    tauri::async_runtime::spawn_blocking(move || {
        let result = toggle_tun_mode_and_restart(&app, &item, runtime.clone(), config_path);
        TRAY_TUN_TOGGLE_IN_PROGRESS.store(false, Ordering::SeqCst);
        if let Err(err) = result {
            let config_path = current_ui_config_path(&runtime);
            let _ = item.set_checked(tun_enabled_for_path(config_path.as_deref()));
            emit_to_main(&app, "agent-tray-error", err);
        }
    });
}

#[cfg(any(windows, target_os = "macos"))]
fn toggle_tun_mode_and_restart(
    app: &tauri::AppHandle,
    item: &tauri::menu::CheckMenuItem<tauri::Wry>,
    runtime: Arc<AgentRuntime>,
    config_path: Option<PathBuf>,
) -> Result<(), String> {
    let config = toggle_tun_enabled_in_config(config_path.as_deref())?;
    let enabled = config.summary.tun_enabled;
    let restart_path = config.path.clone();
    remember_current_ui_config_path(&runtime, &restart_path);
    let _ = item.set_checked(enabled);
    emit_to_main(app, "agent-config-updated", config);

    let state = get_agent_state_inner(&runtime)?;
    emit_to_main(app, "agent-state-updated", state.clone());
    if !state.running {
        return Ok(());
    }

    emit_to_main(app, "agent-tray-info", "正在重启 Agent 以应用 TUN 模式");
    let stopped = stop_agent_inner_command(&runtime)?;
    emit_to_main(app, "agent-state-updated", stopped);
    let started = start_agent_command(&runtime, restart_path)?;
    let running = started.running;
    emit_to_main(app, "agent-state-updated", started);
    if !running {
        return Err("Agent 已重启，但当前未处于运行状态".to_string());
    }
    let status = if enabled { "启用" } else { "关闭" };
    emit_to_main(
        app,
        "agent-tray-info",
        format!("Agent 已重启，TUN 模式已{status}"),
    );

    Ok(())
}

#[cfg(any(windows, target_os = "macos"))]
fn emit_to_main<S>(app: &tauri::AppHandle, event: &str, payload: S)
where
    S: Serialize + Clone,
{
    let _ = app.emit_to("main", event, payload.clone());
    let _ = app.emit(event, payload);
}

#[cfg(any(windows, target_os = "macos"))]
fn remember_current_ui_config_path(runtime: &AgentRuntime, path: &str) {
    if let Ok(mut config_path) = runtime.ui_config_path.lock() {
        *config_path = Some(PathBuf::from(path));
    }
}

#[cfg(any(windows, target_os = "macos"))]
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

#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn hide_window_to_tray_after_minimize(window: tauri::Window) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        if window.is_minimized().unwrap_or(false) {
            hide_window_to_tray(&window);
        }
    });
}

#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn hide_window_to_tray(window: &tauri::Window) {
    set_macos_dock_visibility(window.app_handle(), false);
    let _ = window.hide();
}

pub(crate) fn restore_main_window(app: &tauri::AppHandle) {
    set_macos_dock_visibility(app, true);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(target_os = "macos")]
fn set_macos_dock_visibility(app: &tauri::AppHandle, visible: bool) {
    let _ = app.set_dock_visibility(visible);
}

#[cfg(not(target_os = "macos"))]
fn set_macos_dock_visibility(_app: &tauri::AppHandle, _visible: bool) {}
