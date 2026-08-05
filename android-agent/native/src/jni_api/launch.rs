use super::*;

pub(super) fn start_agent<'local>(
    env: &mut Env<'local>,
    tun_fd: jint,
    config_json: JString<'local>,
    vpn_service: JObject<'local>,
) -> jlong {
    let json: String = match config_json.try_to_string(env) {
        Ok(value) => value,
        Err(err) => {
            throw(env, format!("failed to read config JSON: {err}"));
            return 0;
        }
    };

    let config: AndroidAgentConfig = match serde_json::from_str(&json) {
        Ok(config) => config,
        Err(err) => {
            throw(env, format!("invalid config JSON: {err}"));
            return 0;
        }
    };

    if let Err(err) = socket_protector::install(env, vpn_service) {
        throw(
            env,
            format!("failed to install Android socket protector: {err}"),
        );
        return 0;
    }

    let async_runtime_stack_size = config.async_runtime_stack_size_mb.max(1) * 1024 * 1024;
    let runtime_threads = config.runtime_threads.max(1);
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let authentication_state = Arc::new(VerifiedAuthenticationState::default());
    let task_authentication_state = authentication_state.clone();
    let authentication_username = config.username.clone();
    let raw_fd = tun_fd as RawFd;
    let thread = match std::thread::Builder::new()
        .name("ppaass-android-agent".to_string())
        .stack_size(async_runtime_stack_size)
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("ppaass-android-agent-worker")
                .thread_stack_size(async_runtime_stack_size)
                .worker_threads(runtime_threads)
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    tracing::error!(error = %err, "failed to create Android Agent Tokio runtime");
                    return;
                }
            };

            let monitor_shutdown = task_shutdown.clone();
            let authentication_statuses = common::subscribe_verified_proxy_auth_statuses();
            let result = runtime.block_on(async move {
                let authentication_monitor =
                    tokio::spawn(monitor_verified_authentication_statuses(
                        task_authentication_state,
                        authentication_username,
                        authentication_statuses,
                        monitor_shutdown,
                    ));
                let result = run_android_agent(raw_fd, config, task_shutdown.clone()).await;
                task_shutdown.cancel();
                let _ = authentication_monitor.await;
                result
            });
            if let Err(err) = result {
                tracing::error!(error = %err, "Android Agent stopped");
            }
        }) {
        Ok(thread) => thread,
        Err(err) => {
            socket_protector::clear();
            throw(env, format!("failed to spawn native agent thread: {err}"));
            return 0;
        }
    };

    Box::into_raw(Box::new(AgentHandle {
        shutdown,
        thread: Some(thread),
        clear_socket_protector_on_stop: true,
        authentication_state,
    })) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_startHttpProxy<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
    listen_port: jint,
) -> jlong {
    crate::android_log::install_tracing();
    env.with_env(|env| -> jni::errors::Result<jlong> {
        Ok(start_http_proxy(env, config_json, listen_port))
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

pub(super) fn start_http_proxy<'local>(
    env: &mut Env<'local>,
    config_json: JString<'local>,
    listen_port: jint,
) -> jlong {
    if listen_port <= 0 || listen_port > u16::MAX as jint {
        throw(
            env,
            format!("invalid HTTP proxy listen port: {listen_port}"),
        );
        return 0;
    }

    let json: String = match config_json.try_to_string(env) {
        Ok(value) => value,
        Err(err) => {
            throw(env, format!("failed to read HTTP proxy config JSON: {err}"));
            return 0;
        }
    };

    let config: AndroidAgentConfig = match serde_json::from_str(&json) {
        Ok(config) => config,
        Err(err) => {
            throw(env, format!("invalid HTTP proxy config JSON: {err}"));
            return 0;
        }
    };

    let async_runtime_stack_size = config.async_runtime_stack_size_mb.max(1) * 1024 * 1024;
    let runtime_threads = config.runtime_threads.max(1);
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let authentication_state = Arc::new(VerifiedAuthenticationState::default());
    let task_authentication_state = authentication_state.clone();
    let authentication_username = config.username.clone();
    let port = listen_port as u16;
    let thread = match std::thread::Builder::new()
        .name("ppaass-android-http-proxy".to_string())
        .stack_size(async_runtime_stack_size)
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("ppaass-android-http-proxy-worker")
                .thread_stack_size(async_runtime_stack_size)
                .worker_threads(runtime_threads)
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "failed to create Android HTTP proxy Tokio runtime"
                    );
                    return;
                }
            };

            let monitor_shutdown = task_shutdown.clone();
            let authentication_statuses = common::subscribe_verified_proxy_auth_statuses();
            let result = runtime.block_on(async move {
                let authentication_monitor =
                    tokio::spawn(monitor_verified_authentication_statuses(
                        task_authentication_state,
                        authentication_username,
                        authentication_statuses,
                        monitor_shutdown,
                    ));
                let result = run_android_http_proxy(config, port, task_shutdown.clone()).await;
                task_shutdown.cancel();
                let _ = authentication_monitor.await;
                result
            });
            if let Err(err) = result {
                tracing::error!(error = %err, "Android HTTP proxy stopped");
            }
        }) {
        Ok(thread) => thread,
        Err(err) => {
            throw(
                env,
                format!("failed to spawn native HTTP proxy thread: {err}"),
            );
            return 0;
        }
    };

    Box::into_raw(Box::new(AgentHandle {
        shutdown,
        thread: Some(thread),
        clear_socket_protector_on_stop: false,
        authentication_state,
    })) as jlong
}
