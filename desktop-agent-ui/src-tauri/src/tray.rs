#[cfg(any(windows, target_os = "macos"))]
use std::sync::OnceLock;
#[cfg(any(windows, target_os = "macos"))]
use std::time::Duration;
#[cfg(any(windows, target_os = "macos"))]
use tauri::Emitter;
use tauri::Manager;

#[cfg(any(windows, target_os = "macos"))]
use crate::config::{load_config_from_path, locate_config_path, set_tun_enabled_in_config};

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
pub(crate) fn setup_system_tray(app: &tauri::App) -> Result<(), String> {
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
    let tray_builder = tauri::tray::TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .tooltip("PPAASS Desktop Agent")
        .menu(&menu)
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_menu_event(move |app, event| match event.id().as_ref() {
            TRAY_SHOW_ID => restore_main_window(app),
            TRAY_TUN_ID => handle_tun_menu_event(app, &tun_item_for_event),
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
    locate_config_path()
        .and_then(|path| load_config_from_path(&path).ok())
        .map(|config| config.summary.tun_enabled)
        .unwrap_or(false)
}

#[cfg(any(windows, target_os = "macos"))]
fn handle_tun_menu_event(
    app: &tauri::AppHandle,
    item: &tauri::menu::CheckMenuItem<tauri::Wry>,
) {
    let enabled = item.is_checked().unwrap_or(false);
    match set_tun_enabled_in_config(None, enabled) {
        Ok(config) => {
            let _ = item.set_checked(config.summary.tun_enabled);
            let _ = app.emit("agent-config-updated", config);
        }
        Err(err) => {
            let _ = item.set_checked(!enabled);
            let _ = app.emit("agent-tray-error", err);
        }
    }
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
