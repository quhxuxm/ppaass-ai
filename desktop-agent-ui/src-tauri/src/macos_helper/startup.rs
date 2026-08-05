use super::*;

pub(crate) fn check_macos_tun_helper_on_startup(logs: &UiLogBuffer) {
    let Some(config_path) = locate_config_path() else {
        return;
    };

    let config = match desktop_agent_be::config::AgentConfig::load(&config_path) {
        Ok(config) => config,
        Err(err) => {
            logs.push(format!("跳过 TUN helper 自动检查：读取配置失败：{err}"));
            return;
        }
    };
    if !config_needs_macos_tun_helper(&config) {
        return;
    }

    let (tun_ready, tun_status) = probe_tun_ready(&config.tun.name);
    if tun_ready {
        logs.push(format!(
            "TUN 已在运行，暂不自动检查或更新 helper：{tun_status}。停止后点击启动会再次检查协议版本。"
        ));
        return;
    }

    if let Err(err) = ensure_macos_tun_helper(&config_path, &config, logs) {
        logs.push(format!("TUN helper 自动检查失败：{err}"));
    }
}

pub(crate) fn ensure_macos_tun_helper_for_config(
    config_path: &Path,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let config = desktop_agent_be::config::AgentConfig::load(config_path)
        .map_err(|err| format!("加载 Agent 配置失败：{err}"))?;
    if !config_needs_macos_tun_helper(&config) {
        return Ok(());
    }

    ensure_macos_tun_helper(config_path, &config, logs)
}

pub(crate) fn config_needs_macos_tun_helper(
    config: &desktop_agent_be::config::AgentConfig,
) -> bool {
    config.tun.enabled && config.tun.macos_helper_enabled
}

pub(crate) fn ensure_macos_tun_helper(
    config_path: &Path,
    config: &desktop_agent_be::config::AgentConfig,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let source = std::env::current_exe().map_err(|err| format!("定位当前 App 程序失败：{err}"))?;
    ensure_macos_tun_helper_from_source(&source, config_path, config, logs)
}

pub(crate) fn ensure_macos_tun_helper_from_source(
    source: &Path,
    config_path: &Path,
    config: &desktop_agent_be::config::AgentConfig,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let socket_path = macos_tun_helper_socket(config);
    match macos_tun_helper_status(config) {
        MacosTunHelperStatus::Current => {
            logs.push(format!(
                "TUN helper 协议版本已是当前版本：{}",
                TUN_HELPER_PROTOCOL_VERSION
            ));
            return Ok(());
        }
        MacosTunHelperStatus::Missing => logs.push("TUN helper 未安装，正在请求管理员授权安装"),
        MacosTunHelperStatus::Outdated => logs.push(format!(
            "TUN helper 协议版本不匹配，正在请求管理员授权更新到版本 {}",
            TUN_HELPER_PROTOCOL_VERSION
        )),
        MacosTunHelperStatus::NeedsRestart => {
            logs.push("TUN helper 已安装但未就绪，正在请求管理员授权重启")
        }
    }

    let state_paths = macos_tun_helper_state_paths(config_path, config)?;
    prepare_macos_tun_helper_replacement(config, &state_paths, logs)?;
    install_macos_tun_helper(source, config, &state_paths, logs)?;
    if wait_for_macos_tun_helper_socket(socket_path, Duration::from_secs(6)) {
        request_macos_tun_helper_cleanup(socket_path, &state_paths)
            .map_err(|err| format!("TUN helper 已更新，但启动后的遗留网络状态清理失败：{err}"))?;
        logs.push("TUN helper 已就绪");
        Ok(())
    } else {
        Err(format!("TUN helper socket 未就绪：{socket_path}"))
    }
}

pub(crate) fn macos_tun_helper_socket(config: &desktop_agent_be::config::AgentConfig) -> &str {
    let socket_path = config.tun.macos_helper_socket.trim();
    if socket_path.is_empty() {
        TUN_HELPER_SOCKET_PATH
    } else {
        socket_path
    }
}

pub fn macos_tun_helper_state_paths(
    _config_path: &Path,
    config: &desktop_agent_be::config::AgentConfig,
) -> Result<MacosTunHelperStatePaths, String> {
    let socket_path = Path::new(macos_tun_helper_socket(config));
    if !socket_path.is_absolute() {
        return Err(format!(
            "TUN helper socket 必须使用绝对路径：{}",
            socket_path.display()
        ));
    }
    Ok(MacosTunHelperStatePaths {
        route: tun_helper_route_state_path(socket_path),
        dns: tun_helper_dns_state_path(socket_path),
        lease: macos_tun_helper_lease_state_path(socket_path),
    })
}

pub fn macos_tun_helper_lease_state_path(socket_path: &Path) -> PathBuf {
    let mut file_name = socket_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("tun-helper.sock"))
        .to_os_string();
    file_name.push(TUN_HELPER_LEASE_STATE_SUFFIX);
    socket_path.with_file_name(file_name)
}
