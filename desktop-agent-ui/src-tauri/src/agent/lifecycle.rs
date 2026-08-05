use super::*;

pub(crate) fn get_agent_state_inner(runtime: &AgentRuntime) -> Result<AgentState, String> {
    #[cfg(windows)]
    if windows_service_matches_current_exe().unwrap_or(false) {
        match windows_service_state() {
            Ok(state) => return Ok(state),
            Err(err) if windows_service_is_running().unwrap_or(false) => return Err(err),
            Err(_) => return agent_state_from_status(runtime, false, None),
        }
    }

    agent_state(runtime)
}

pub(crate) fn start_agent_command(
    runtime: &AgentRuntime,
    config_path: String,
) -> Result<AgentState, String> {
    let session = runtime.require_authenticated_session()?;
    validate_managed_proxy_addresses(&session.proxy_addresses, false)?;
    let (candidate, _) =
        enforce_managed_config_path_for_account(Path::new(&config_path), &session.account)?;
    validate_config_candidate_against_trusted_baseline(runtime, &session.account, &candidate)?;
    if !session
        .account
        .has_permission(AGENT_PACKET_CAPTURE_PERMISSION)
    {
        runtime
            .packet_capture_enabled
            .store(false, Ordering::Release);
    }

    #[cfg(windows)]
    {
        start_agent_via_windows_service(config_path, &runtime.logs)
    }

    #[cfg(not(windows))]
    start_agent_inner(
        runtime,
        PathBuf::from(config_path),
        session.proxy_addresses,
        true,
    )
}

pub(crate) fn start_agent_inner(
    runtime: &AgentRuntime,
    config_path: PathBuf,
    proxy_addresses: Vec<String>,
    allow_elevation: bool,
) -> Result<AgentState, String> {
    validate_managed_proxy_addresses(&proxy_addresses, false)?;
    apply_log_level_from_config_path(runtime, &config_path)?;

    let (running, _) = process_status(runtime)?;
    if running {
        return agent_state(runtime);
    }

    if allow_elevation {
        ensure_start_privileges(&config_path)?;
    }
    #[cfg(target_os = "macos")]
    if allow_elevation {
        ensure_macos_tun_helper_for_config(&config_path, &runtime.logs)?;
    }
    stop_external_agent(&config_path)?;
    if let Ok(mut last_error) = runtime.last_error.lock() {
        *last_error = None;
    }
    let embedded = spawn_embedded_agent(
        config_path.clone(),
        proxy_addresses,
        runtime.logs.clone(),
        runtime.last_error.clone(),
        runtime.packet_capture_enabled.load(Ordering::Acquire),
        cfg!(windows) && !allow_elevation,
    )?;
    runtime
        .packet_capture_enabled
        .store(embedded.packet_capture.is_enabled(), Ordering::Release);

    *runtime
        .config_path
        .lock()
        .map_err(|_| "配置路径状态锁已损坏".to_string())? = Some(config_path);
    *runtime
        .agent
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())? = Some(embedded);

    wait_for_agent_start(runtime)?;
    agent_state(runtime)
}

pub(crate) fn stop_agent_inner_command(runtime: &AgentRuntime) -> Result<AgentState, String> {
    #[cfg(windows)]
    {
        if windows_service_is_running()? {
            return stop_agent_via_windows_service();
        }
        agent_state(runtime)
    }

    #[cfg(not(windows))]
    {
        stop_embedded_agent(runtime)?;
        agent_state(runtime)
    }
}

pub(crate) fn restart_agent_after_managed_config_update(
    runtime: &AgentRuntime,
    config_path: &Path,
    start_when_stopped: bool,
) -> Result<AgentState, String> {
    let current = get_agent_state_inner(runtime)?;
    if !current.running && !start_when_stopped {
        return Ok(current);
    }
    if current.running {
        let stopped = stop_agent_inner_command(runtime)?;
        if stopped.running {
            return Err("Agent 未能停止，无法应用最新受管配置".to_string());
        }
    }
    #[cfg(windows)]
    {
        start_agent_via_windows_service(config_path.to_string_lossy().to_string(), &runtime.logs)
    }
    #[cfg(not(windows))]
    {
        // 权限同步不得触发 helper 安装或升级；仅复用当前产品运行路径。
        let session = runtime.require_authenticated_session()?;
        start_agent_inner(
            runtime,
            config_path.to_path_buf(),
            session.proxy_addresses,
            false,
        )
    }
}

pub(crate) fn stop_embedded_agent(runtime: &AgentRuntime) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let agent_to_join = {
            let mut guard = runtime
                .agent
                .lock()
                .map_err(|_| "进程状态锁已损坏".to_string())?;

            let Some(agent) = guard.as_ref() else {
                return Ok(());
            };
            agent.shutdown.cancel();

            if agent.join.is_none() {
                let _ = guard.take();
                return Ok(());
            }

            if agent.join.as_ref().is_some_and(JoinHandle::is_finished) {
                guard.take()
            } else {
                None
            }
        };

        if let Some(mut agent) = agent_to_join {
            if let Some(join) = agent.join.take() {
                let _ = join.join();
            }
            return Ok(());
        }

        if started.elapsed() >= AGENT_STOP_TIMEOUT {
            runtime.logs.push(format!(
                "Agent 停止超时：已等待 {} 秒，后台任务仍未退出",
                AGENT_STOP_TIMEOUT.as_secs()
            ));
            return Err(format!(
                "Agent 停止超时（超过 {} 秒），后台任务仍在退出中",
                AGENT_STOP_TIMEOUT.as_secs()
            ));
        }

        thread::sleep(AGENT_STOP_POLL_INTERVAL);
    }
}

pub(crate) fn agent_state(runtime: &AgentRuntime) -> Result<AgentState, String> {
    let (running, pid) = process_status(runtime)?;
    agent_state_from_status(runtime, running, pid)
}

pub(crate) fn agent_state_from_status(
    runtime: &AgentRuntime,
    running: bool,
    pid: Option<u32>,
) -> Result<AgentState, String> {
    let config_path = runtime
        .config_path
        .lock()
        .map_err(|_| "配置路径状态锁已损坏".to_string())?
        .clone()
        .or_else(locate_config_path);

    Ok(AgentState {
        running,
        managed: true,
        pid,
        config_path: config_path.map(|path| path.to_string_lossy().to_string()),
        binary_path: std::env::current_exe()
            .ok()
            .map(|path| path.to_string_lossy().to_string()),
        logs: runtime.logs.snapshot(),
    })
}

pub(crate) fn apply_ui_log_level(runtime: &AgentRuntime, log_level: &str) {
    if let Err(err) = runtime.logs.set_log_level(log_level) {
        runtime.logs.push(err);
    }
}

pub(crate) fn apply_log_level_from_config_path(
    runtime: &AgentRuntime,
    config_path: &Path,
) -> Result<(), String> {
    let config = desktop_agent_be::config::AgentConfig::load(config_path)
        .map_err(|err| format!("加载 Agent 配置失败：{err}"))?;
    apply_ui_log_level(runtime, &config.log_level);
    Ok(())
}

pub(crate) fn process_status(runtime: &AgentRuntime) -> Result<(bool, Option<u32>), String> {
    let mut guard = runtime
        .agent
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?;

    match guard.as_mut() {
        Some(agent) if agent.join.as_ref().is_some_and(JoinHandle::is_finished) => {
            if let Some(join) = agent.join.take() {
                let _ = join.join();
            }
            *guard = None;
            Ok((false, None))
        }
        Some(_) => Ok((true, Some(std::process::id()))),
        None => Ok((false, None)),
    }
}

pub(crate) fn spawn_embedded_agent(
    config_path: PathBuf,
    proxy_addresses: Vec<String>,
    logs: UiLogBuffer,
    last_error: Arc<Mutex<Option<String>>>,
    resume_packet_capture: bool,
    enforce_trusted_windows_assets: bool,
) -> Result<EmbeddedAgent, String> {
    let agent_base_dir = agent_base_dir(&config_path);
    let mut config = desktop_agent_be::config::AgentConfig::load(&config_path)
        .map_err(|err| format!("加载 Agent 配置失败：{err}"))?;
    normalize_agent_config_paths(&mut config, &agent_base_dir);
    #[cfg(windows)]
    if enforce_trusted_windows_assets {
        config.tun.wintun_file = Some(
            trusted_windows_wintun_path()?
                .to_string_lossy()
                .into_owned(),
        );
    }
    #[cfg(not(windows))]
    let _ = enforce_trusted_windows_assets;
    config.log_dir = None;
    #[cfg(target_os = "macos")]
    {
        config.tun.macos_helper_fallback_to_privilege = false;
    }
    let shutdown = CancellationToken::new();
    let shutdown_for_thread = shutdown.clone();
    let thread_logs = logs.clone();
    let thread_error = last_error.clone();
    let stack_size = config.async_runtime_stack_size_mb * 1024 * 1024;
    let runtime_threads = config.runtime_threads;
    let packet_capture = desktop_agent_be::PacketCaptureController::new(PathBuf::from(
        &config.tun.packet_capture.file,
    ));
    if resume_packet_capture {
        match packet_capture.set_enabled(true) {
            Ok(()) => logs.push("Agent 重启后已继续抓包"),
            Err(error) => logs.push(format!("Agent 重启后恢复抓包失败，将保持关闭：{error}")),
        }
    }
    let thread_packet_capture = packet_capture.clone();

    logs.push(format!(
        "准备以内嵌模式启动 Agent：{}",
        config_path.to_string_lossy()
    ));
    logs.push(format!("Agent 资源目录：{}", agent_base_dir.display()));
    if config.tun.enabled {
        if let Some(wintun_file) = config.tun.wintun_file.as_deref() {
            logs.push(format!("Windows TUN 运行库：{wintun_file}"));
        }
    }

    let join = thread::Builder::new()
        .name("ppaass-embedded-agent".to_string())
        .spawn(move || {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.thread_stack_size(stack_size).enable_all();
            if let Some(threads) = runtime_threads {
                builder.worker_threads(threads);
            }

            match builder.build() {
                Ok(runtime) => {
                    let result = runtime.block_on(desktop_agent_be::run_agent_with_packet_capture(
                        config,
                        proxy_addresses,
                        shutdown_for_thread,
                        thread_packet_capture,
                    ));
                    if let Err(err) = result {
                        let message = format!("内嵌 Agent 异常停止：{err}");
                        if let Ok(mut last_error) = thread_error.lock() {
                            *last_error = Some(message.clone());
                        }
                        tracing::error!("{message}");
                    }
                }
                Err(err) => {
                    let message = format!("创建内嵌 Agent Tokio runtime 失败：{err}");
                    if let Ok(mut last_error) = thread_error.lock() {
                        *last_error = Some(message.clone());
                    }
                    thread_logs.push(message);
                }
            }
        })
        .map_err(|err| format!("启动内嵌 Agent 线程失败：{err}"))?;

    Ok(EmbeddedAgent {
        shutdown,
        join: Some(join),
        packet_capture,
    })
}
