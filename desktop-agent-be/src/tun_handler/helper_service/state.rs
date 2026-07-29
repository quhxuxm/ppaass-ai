use super::*;

pub(super) fn helper_lease_state_path(socket_path: &Path) -> PathBuf {
    let mut file_name = socket_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("tun-helper.sock"))
        .to_os_string();
    file_name.push(HELPER_LEASE_STATE_SUFFIX);
    socket_path.with_file_name(file_name)
}

pub(super) fn confine_requested_state_path(
    kind: &str,
    requested: Option<&str>,
    trusted: &Path,
) -> Result<String> {
    if let Some(requested) = requested.map(str::trim).filter(|path| !path.is_empty())
        && Path::new(requested) != trusted
    {
        anyhow::bail!(
            "拒绝 TUN helper {kind} 状态路径越界：请求={}，允许={}",
            requested,
            trusted.display()
        );
    }
    Ok(trusted.to_string_lossy().into_owned())
}

pub(super) fn validate_persisted_lease_state_paths(
    metadata: &PersistedTunLease,
    trusted_route: &Path,
    trusted_dns: &Path,
) -> Result<()> {
    let route_state = metadata.route_state_file.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "TUN helper v4 lease={} 缺少受信任 route 状态路径，拒绝恢复旧状态",
            metadata.lease_id
        )
    })?;
    let dns_state = metadata.dns_state_file.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "TUN helper v4 lease={} 缺少受信任 dns 状态路径，拒绝恢复旧状态",
            metadata.lease_id
        )
    })?;
    if Path::new(route_state) != trusted_route || Path::new(dns_state) != trusted_dns {
        anyhow::bail!(
            "TUN helper v4 lease={} 状态路径不受信任：route={} dns={}，允许 route={} dns={}",
            metadata.lease_id,
            route_state,
            dns_state,
            trusted_route.display(),
            trusted_dns.display()
        );
    }
    if let Some(recovery) = metadata.route_recovery.as_ref()
        && (recovery.request.route_state_file.as_deref() != Some(route_state)
            || recovery.request.dns_state_file.as_deref() != Some(dns_state))
    {
        anyhow::bail!(
            "TUN helper v4 lease={} 的嵌套路由恢复路径与顶层元数据不一致，拒绝恢复",
            metadata.lease_id
        );
    }
    Ok(())
}

pub(super) fn load_persisted_leases(path: &Path) -> Result<Vec<PersistedTunLease>> {
    let content = match fs::read(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("读取 TUN helper lease 状态失败：{}", path.display()));
        }
    };
    let state: PersistedLeaseState = serde_json::from_slice(&content)
        .with_context(|| format!("解析 TUN helper lease 状态失败：{}", path.display()))?;
    if state.version != HELPER_LEASE_STATE_VERSION {
        anyhow::bail!(
            "不支持的 TUN helper lease 状态版本：文件={} 版本={} 当前={}",
            path.display(),
            state.version,
            HELPER_LEASE_STATE_VERSION
        );
    }
    Ok(state.leases)
}

pub(super) fn persist_lease_state(path: &Path, state: &PersistedLeaseState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("创建 helper lease 状态目录失败：{}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(state).context("序列化 TUN helper lease 状态失败")?;
    let tmp_path = path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        HELPER_LEASE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp_path)
        .with_context(|| format!("创建 helper lease 临时状态失败：{}", tmp_path.display()))?;
    let persist_result = (|| {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("设置 helper lease 状态权限失败：{}", tmp_path.display()))?;
        file.write_all(&data)
            .with_context(|| format!("写入 helper lease 临时状态失败：{}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("同步 helper lease 临时状态失败：{}", tmp_path.display()))?;
        fs::rename(&tmp_path, path)
            .with_context(|| format!("提交 helper lease 状态失败：{}", path.display()))?;
        sync_parent_directory(path)
    })();
    if persist_result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    persist_result
}

pub(super) fn sync_parent_directory(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)
        .with_context(|| format!("打开 helper lease 状态目录失败：{}", parent.display()))?
        .sync_all()
        .with_context(|| format!("同步 helper lease 状态目录失败：{}", parent.display()))
}

pub(super) fn lease_owner_is_alive(metadata: &PersistedTunLease) -> bool {
    if metadata.cleanup_requested {
        return false;
    }
    let Some(expected_start_time) = metadata.owner_start_time else {
        return false;
    };
    process_start_time(metadata.owner_pid) == Some(expected_start_time)
}

pub(super) fn process_start_time(pid: u32) -> Option<ProcessStartTime> {
    let Ok(pid) = i32::try_from(pid) else {
        return None;
    };
    if pid <= 0 {
        return None;
    }
    let mut info = unsafe { mem::zeroed::<libc::proc_bsdinfo>() };
    let expected_size = mem::size_of::<libc::proc_bsdinfo>();
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            expected_size as i32,
        )
    };
    if result != expected_size as i32 || info.pbi_pid != pid as u32 || info.pbi_start_tvsec == 0 {
        return None;
    }
    Some(ProcessStartTime {
        unix_secs: info.pbi_start_tvsec,
        micros: info.pbi_start_tvusec,
    })
}

pub(super) fn lease_state_files_remain(metadata: &PersistedTunLease) -> bool {
    lease_state_files_remain_at(
        metadata.route_state_file.as_deref(),
        metadata.dns_state_file.as_deref(),
    )
}

pub(super) fn lease_state_files_remain_at(
    route_state_file: Option<&str>,
    dns_state_file: Option<&str>,
) -> bool {
    [route_state_file, dns_state_file]
        .into_iter()
        .flatten()
        .any(|path| !path.trim().is_empty() && Path::new(path).exists())
}

pub(super) fn restore_route_guard(
    metadata: &PersistedTunLease,
    pf_token_observer: &mut dyn FnMut(Option<&str>) -> AgentResult<()>,
) -> AgentResult<RouteGuard> {
    let recovery = metadata.route_recovery.as_ref().ok_or_else(|| {
        AgentError::Connection(format!(
            "lease={} 缺少完整路由/PF 恢复参数，不能安全接管",
            metadata.lease_id
        ))
    })?;
    let current_name = interface_name_for_index(recovery.tun_if_index).ok_or_else(|| {
        AgentError::Connection(format!(
            "lease={} 的 TUN if_index={} 已不存在，不能恢复路由/PF",
            metadata.lease_id, recovery.tun_if_index
        ))
    })?;
    if current_name != recovery.actual_name {
        return Err(AgentError::Connection(format!(
            "lease={} 的 TUN 接口已变化：期望={} 实际={}，拒绝向错误接口恢复路由/PF",
            metadata.lease_id, recovery.actual_name, current_name
        )));
    }
    RouteGuard::install_with_pf_token_observer(
        RouteGuardInstall {
            tun_if_index: recovery.tun_if_index,
            tun_ipv4: recovery.tun_ipv4,
            dns_capture_target: recovery.dns_capture_target,
            tun_ipv6_cidr: recovery.request.ipv6.as_deref(),
            route_state_file: metadata.route_state_file.as_deref(),
            proxy_ips: &recovery.proxy_ips,
            capture_system_dns: recovery.request.proxy_dns,
        },
        pf_token_observer,
    )
}

pub(super) fn interface_name_for_index(if_index: u32) -> Option<String> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    let pointer = unsafe { libc::if_indextoname(if_index, name.as_mut_ptr()) };
    if pointer.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned(),
    )
}
