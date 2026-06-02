#[cfg(any(windows, target_os = "macos"))]
use std::time::Duration;
use tauri::Manager;

#[cfg(any(windows, target_os = "macos"))]
const TRAY_ID: &str = "main";
#[cfg(any(windows, target_os = "macos"))]
const TRAY_SHOW_ID: &str = "show";
#[cfg(any(windows, target_os = "macos"))]
const TRAY_EXIT_ID: &str = "exit";
#[cfg(any(windows, target_os = "macos"))]
const TRAY_ICON_BYTES: &[u8] = include_bytes!("../icons/32x32.png");

#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn setup_system_tray(app: &tauri::App) -> Result<(), String> {
    let icon = tauri::image::Image::from_bytes(TRAY_ICON_BYTES)
        .map(|icon| icon.to_owned())
        .map_err(|err| format!("加载应用托盘图标失败：{err}"))?;
    let menu = tauri::menu::MenuBuilder::new(app)
        .text(TRAY_SHOW_ID, "显示")
        .separator()
        .text(TRAY_EXIT_ID, "退出")
        .build()
        .map_err(|err| format!("创建系统托盘菜单失败：{err}"))?;

    let tray_builder = tauri::tray::TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .tooltip("PPAASS Desktop Agent")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            TRAY_SHOW_ID => restore_main_window(app),
            TRAY_EXIT_ID => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
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
