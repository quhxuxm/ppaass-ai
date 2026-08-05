use super::*;

pub fn run() {
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
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            restore_main_window(app);
        }))
        .setup(move |app| {
            install_bundled_agent_assets(app, &setup_logs).map_err(io::Error::other)?;
            if let Err(error) = restore_agent_login_on_startup(app.handle(), &setup_runtime) {
                let message =
                    format!("恢复 Agent 长期登录状态失败：{error}；旧会话不再兼容，请重新登录");
                setup_logs.push(message.clone());
                let _ = setup_runtime.set_permission_sync_error(Some(message));
                if let Err(stop_error) = stop_agent_inner_command(&setup_runtime) {
                    setup_logs.push(format!("停止旧 Agent 失败：{stop_error}"));
                }
            }
            start_agent_server_events(app.handle().clone(), setup_runtime.clone());
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
            open_user_account_management,
            login_and_provision_agent,
            rotate_agent_key,
            start_agent_device_login,
            poll_agent_device_login,
            cancel_agent_device_login,
            logout_agent,
            load_agent_config,
            save_agent_config,
            save_agent_config_summary,
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
            get_agent_admin_key_request_inbox,
            refresh_agent_admin_key_requests,
            approve_agent_admin_key_request_command,
            reject_agent_admin_key_request_command,
        ])
        .run(tauri::generate_context!())
        .expect("error while running PPAASS Desktop Agent UI");
}
