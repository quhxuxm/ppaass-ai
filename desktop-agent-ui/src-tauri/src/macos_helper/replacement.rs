use super::*;

pub(crate) fn prepare_macos_tun_helper_replacement(
    config: &desktop_agent_be::config::AgentConfig,
    state_paths: &MacosTunHelperStatePaths,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let active_reasons = active_macos_tun_replacement_reasons(config, state_paths)?;
    if !active_reasons.is_empty() {
        return Err(format!(
            "检测到活动 TUN，拒绝覆盖或重启 helper：{}。请先停止当前 Agent/TUN，确认网络恢复后再重试",
            active_reasons.join("；")
        ));
    }

    let socket_path = macos_tun_helper_socket(config);
    match macos_tun_helper_ping(socket_path) {
        Ok(()) => {
            logs.push(format!(
                "更新 TUN helper 前先清理现有 lease/路由状态：route={} dns={} lease={}",
                state_paths.route.display(),
                state_paths.dns.display(),
                state_paths.lease.display()
            ));
            request_macos_tun_helper_cleanup(socket_path, state_paths)?;
            verify_macos_tun_helper_routes_clean(config, state_paths)?;
            logs.push("现有 TUN helper 已确认完成更新前网络状态清理");
            Ok(())
        }
        Err(probe_error) => {
            if macos_tun_helper_process_running() {
                return Err(format!(
                    "拒绝覆盖或重启 TUN helper：旧 helper 进程仍在运行，但控制接口不可用，无法确认其 lease 已安全清理（{probe_error}）"
                ));
            }
            let stale_state = existing_macos_tun_helper_state_files(state_paths)?;
            if !stale_state.is_empty() {
                return Err(format!(
                    "旧 TUN helper 不可连接且仍有恢复状态，拒绝直接删除：{}（{probe_error}）",
                    stale_state.join("；")
                ));
            }
            logs.push(format!(
                "旧 TUN helper 不可连接，但未发现活动 lease/路由，可安全安装：{probe_error}"
            ));
            Ok(())
        }
    }
}

pub(crate) fn active_macos_tun_replacement_reasons(
    config: &desktop_agent_be::config::AgentConfig,
    _state_paths: &MacosTunHelperStatePaths,
) -> Result<Vec<String>, String> {
    let mut reasons = Vec::new();
    let (tun_ready, tun_status) = probe_tun_ready(&config.tun.name);
    if tun_ready {
        reasons.push(tun_status);
    } else if macos_managed_tun_route_active(&config.tun.name) {
        reasons.push("至少一条系统分流路由仍由 TUN 接管".to_string());
    }
    Ok(reasons)
}

pub fn existing_macos_tun_helper_state_files(
    state_paths: &MacosTunHelperStatePaths,
) -> Result<Vec<String>, String> {
    let mut existing = Vec::new();
    for (label, path) in [
        ("路由状态", &state_paths.route),
        ("DNS 状态", &state_paths.dns),
        ("helper lease 状态", &state_paths.lease),
    ] {
        if state_file_exists(path)? {
            existing.push(format!("{label}文件仍存在：{}", path.display()));
        }
    }
    Ok(existing)
}

pub(crate) fn verify_macos_tun_helper_routes_clean(
    config: &desktop_agent_be::config::AgentConfig,
    state_paths: &MacosTunHelperStatePaths,
) -> Result<(), String> {
    let remaining_state = existing_macos_tun_helper_state_files(state_paths)?;
    if !remaining_state.is_empty() {
        return Err(format!(
            "旧 helper 返回清理成功，但仍有恢复状态，拒绝重启：{}",
            remaining_state.join("；")
        ));
    }
    if macos_managed_tun_route_active(&config.tun.name) {
        return Err("旧 helper 返回清理成功，但系统流量仍由 TUN 路由接管，拒绝重启".to_string());
    }
    Ok(())
}

pub(crate) fn state_file_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "检查 TUN helper 状态文件失败：{}：{err}",
            path.display()
        )),
    }
}

pub(crate) fn macos_tun_helper_process_running() -> bool {
    launchd_job_has_pid(TUN_HELPER_PLIST_ID) || launchd_job_has_pid(TUN_HELPER_LEGACY_PLIST_ID)
}

pub(crate) fn launchd_job_has_pid(label: &str) -> bool {
    let output = match Command::new("launchctl")
        .args(["print", &format!("system/{label}")])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return false,
    };
    launchd_print_has_pid(&String::from_utf8_lossy(&output.stdout))
}

pub fn launchd_print_has_pid(output: &str) -> bool {
    output.lines().any(|line| {
        line.trim()
            .strip_prefix("pid = ")
            .is_some_and(|pid| pid.trim().parse::<u32>().is_ok_and(|pid| pid > 0))
    })
}

pub(crate) fn macos_managed_tun_route_active(configured_tun_name: &str) -> bool {
    ["1.1.1.1", "200.0.0.1"].iter().any(|target| {
        macos_route_interface(target)
            .as_deref()
            .is_some_and(|interface| tun_interface_matches(interface, configured_tun_name))
    })
}

pub(crate) fn macos_route_interface(target: &str) -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", target])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_macos_route_interface(&String::from_utf8_lossy(&output.stdout))
}

pub fn parse_macos_route_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(str::trim)
            .filter(|interface| !interface.is_empty())
            .map(ToOwned::to_owned)
    })
}

pub fn tun_interface_matches(interface: &str, configured_tun_name: &str) -> bool {
    interface == configured_tun_name
        || (interface.starts_with("utun") && configured_tun_name.starts_with("utun"))
}
