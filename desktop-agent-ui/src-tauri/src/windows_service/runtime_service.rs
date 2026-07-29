use super::*;

pub(crate) fn windows_service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(err) = run_windows_service_inner() {
        eprintln!("PPAASS Agent Service failed: {err}");
    }
}

pub(crate) fn run_windows_service_inner() -> Result<(), String> {
    let runtime = Arc::new(AgentRuntime::new());
    runtime.logs.install_tracing();
    runtime.logs.push("PPAASS Agent Windows Service 启动");
    let shutdown = CancellationToken::new();
    let shutdown_for_handler = shutdown.clone();

    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown_for_handler.cancel();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(|err| format!("注册 Windows Service 控制处理器失败：{err}"))?;

    set_service_status(&status_handle, ServiceState::Running)?;

    let auth_failure_thread =
        spawn_service_auth_failure_listener(runtime.clone(), shutdown.clone())
            .map_err(|err| format!("启动 Proxy 账号状态监听失败：{err}"))?;
    restore_desired_agent_on_service_start(&runtime);

    let ipc_runtime = runtime.clone();
    let ipc_shutdown = shutdown.clone();
    let ipc_thread = thread::Builder::new()
        .name("ppaass-agent-service-ipc".to_string())
        .spawn(move || run_service_ipc(ipc_runtime, ipc_shutdown))
        .map_err(|err| format!("启动服务 IPC 失败：{err}"))?;

    while !shutdown.is_cancelled() {
        std::thread::sleep(Duration::from_millis(300));
    }

    let _ = stop_embedded_agent(&runtime);
    let _ = ipc_thread.join();
    let _ = auth_failure_thread.join();
    set_service_status(&status_handle, ServiceState::Stopped)?;
    Ok(())
}

pub(crate) fn restore_desired_agent_on_service_start(runtime: &AgentRuntime) {
    let desired_login = match service_desired_running() {
        Ok(desired_login) => desired_login,
        Err(error) => {
            runtime.logs.push(format!(
                "读取 Windows Service 持久运行状态失败，已安全跳过自动恢复：{error}"
            ));
            return;
        }
    };
    let Some(desired_login) = desired_login else {
        return;
    };

    if let Err(error) = service_session_authorization() {
        runtime.logs.push(format!(
            "Windows Service 存在持久运行请求，但登录授权无效，已安全跳过自动恢复：{error}"
        ));
        return;
    }

    let config_path = service_root_config_path();
    let restored = validate_authorized_service_config_path(&config_path).and_then(
        |(path, current_login, proxy_addresses)| {
            if current_login != desired_login {
                return Err("持久运行请求属于另一组登录凭据，拒绝用当前账号自动恢复".to_string());
            }
            start_agent_inner(runtime, path, proxy_addresses, false)
        },
    );
    match restored {
        Ok(_) => runtime
            .logs
            .push("Windows Service 已恢复上次显式启动的 Agent"),
        Err(error) => runtime.logs.push(format!(
            "Windows Service 无法恢复上次显式启动的 Agent；保留运行请求以便修复后重试：{error}"
        )),
    }
}

pub(crate) fn spawn_service_auth_failure_listener(
    runtime: Arc<AgentRuntime>,
    shutdown: CancellationToken,
) -> Result<thread::JoinHandle<()>, String> {
    let mut statuses = common::subscribe_verified_proxy_auth_statuses();
    thread::Builder::new()
        .name("ppaass-agent-service-auth-status".to_string())
        .spawn(move || {
            let async_runtime = match Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    runtime
                        .logs
                        .push(format!("创建 Proxy 账号状态监听 runtime 失败：{error}"));
                    return;
                }
            };
            async_runtime.block_on(async move {
                loop {
                    let status = tokio::select! {
                        _ = shutdown.cancelled() => break,
                        status = statuses.recv() => match status {
                            Ok(status) => status,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        },
                    };
                    let status = match status {
                        common::VerifiedProxyAuthStatus::Active { username } => {
                            VerifiedProxyAuthStatus {
                                username,
                                status: AgentAuthAccountStatus::Active,
                            }
                        }
                        common::VerifiedProxyAuthStatus::UserExpired { username } => {
                            VerifiedProxyAuthStatus {
                                username,
                                status: AgentAuthAccountStatus::Expired,
                            }
                        }
                        common::VerifiedProxyAuthStatus::UserDisabled { username } => {
                            VerifiedProxyAuthStatus {
                                username,
                                status: AgentAuthAccountStatus::Disabled,
                            }
                        }
                    };
                    if let Err(error) = runtime.set_verified_proxy_auth_status(status) {
                        runtime
                            .logs
                            .push(format!("保存 Proxy 账号状态失败：{error}"));
                    }
                }
            });
        })
        .map_err(|error| error.to_string())
}

pub(crate) fn set_service_status(
    status_handle: &service_control_handler::ServiceStatusHandle,
    current_state: ServiceState,
) -> Result<(), String> {
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(2),
            process_id: None,
        })
        .map_err(|err| format!("设置 Windows Service 状态失败：{err}"))
}

pub(crate) fn run_service_ipc(runtime: Arc<AgentRuntime>, shutdown: CancellationToken) {
    let async_runtime = match Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            runtime
                .logs
                .push(format!("初始化服务 IPC runtime 失败：{err}"));
            return;
        }
    };

    async_runtime.block_on(run_service_ipc_async(runtime, shutdown));
}

pub(crate) async fn run_service_ipc_async(runtime: Arc<AgentRuntime>, shutdown: CancellationToken) {
    let listener = match TcpListener::bind(SERVICE_IPC_ADDR).await {
        Ok(listener) => listener,
        Err(err) => {
            runtime.logs.push(format!("服务 IPC 监听失败：{err}"));
            return;
        }
    };
    runtime
        .logs
        .push(format!("服务 IPC 已监听：{SERVICE_IPC_ADDR}"));
    let mutation_lock = Arc::new(Mutex::new(()));

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let connection_runtime = runtime.clone();
                        let connection_mutation_lock = mutation_lock.clone();
                        tokio::spawn(async move {
                            respond_to_service_request(
                                connection_runtime,
                                connection_mutation_lock,
                                stream,
                            )
                            .await;
                        });
                    }
                    Err(err) => runtime.logs.push(format!("服务 IPC 接收失败：{err}")),
                }
            }
        }
    }
}

pub(crate) async fn respond_to_service_request(
    runtime: Arc<AgentRuntime>,
    mutation_lock: Arc<Mutex<()>>,
    mut stream: TcpStream,
) {
    let response = read_and_handle_service_request(runtime, mutation_lock, &mut stream).await;
    let payload = serde_json::to_vec(&response).unwrap_or_else(|err| {
        format!(
            "{{\"ok\":false,\"state\":null,\"traffic\":null,\"error\":\"编码响应失败：{err}\"}}"
        )
        .into_bytes()
    });
    let _ = timeout(SERVICE_IPC_IO_TIMEOUT, stream.write_all(&payload)).await;
    let _ = timeout(SERVICE_IPC_IO_TIMEOUT, stream.shutdown()).await;
}

pub(crate) async fn read_and_handle_service_request(
    runtime: Arc<AgentRuntime>,
    mutation_lock: Arc<Mutex<()>>,
    stream: &mut TcpStream,
) -> ServiceResponse {
    let mut payload = Vec::new();
    match timeout(
        SERVICE_IPC_IO_TIMEOUT,
        stream
            .take(MAX_SERVICE_IPC_REQUEST_BYTES + 1)
            .read_to_end(&mut payload),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => return service_error(format!("读取服务请求失败：{err}")),
        Err(_) => return service_error("读取服务请求超时".to_string()),
    }
    if payload.len() as u64 > MAX_SERVICE_IPC_REQUEST_BYTES {
        return service_error("服务请求过大，已拒绝处理".to_string());
    }

    let mut envelope = match serde_json::from_slice::<ServiceRequestEnvelope>(&payload) {
        Ok(envelope) => envelope,
        Err(err) => return service_error(format!("解析服务请求失败：{err}")),
    };
    let authorization = authorize_service_request(&envelope.auth_token);
    envelope.auth_token.zeroize();
    if authorization.is_err() {
        return service_error("Windows Service 请求未授权，请重新登录".to_string());
    }
    let request = envelope.request;

    let is_mutating = service_request_is_mutating(&request);
    match task::spawn_blocking(move || {
        if is_mutating {
            let Ok(_guard) = mutation_lock.lock() else {
                return service_error("Agent 服务操作锁已损坏".to_string());
            };
            handle_service_request(&runtime, request)
        } else {
            handle_service_request(&runtime, request)
        }
    })
    .await
    {
        Ok(response) => response,
        Err(err) => service_error(format!("处理服务请求失败：{err}")),
    }
}
