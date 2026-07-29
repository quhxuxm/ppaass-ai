use super::*;

pub(super) fn prepare_tun(request: &TunStartRequest) -> AgentResult<PreparedTun> {
    let (ipv4, ipv4_prefix) = network::parse_cidr_v4(&request.ipv4)?;
    let ipv6_config = request
        .ipv6
        .as_deref()
        .map(network::parse_cidr_v6)
        .transpose()?;

    cleanup_lease_artifacts(
        request.route_state_file.as_deref(),
        request.dns_state_file.as_deref(),
        None,
    )
    .map_err(|err| AgentError::Connection(err.to_string()))?;
    let proxy_ips = resolve_proxy_ips_checked(&request.proxy_addrs)?;

    let mut builder = DeviceBuilder::new()
        .name(&request.name)
        .mtu(request.mtu)
        .ipv4(
            ipv4,
            tun_ipv4_interface_prefix(ipv4_prefix),
            tun_ipv4_destination(ipv4, ipv4_prefix),
        );
    #[cfg(target_os = "macos")]
    {
        builder = builder.associate_route(false);
    }
    if let Some((ipv6, ipv6_prefix)) = ipv6_config {
        builder = builder.ipv6(ipv6, ipv6_prefix);
    }

    let device = builder
        .build_sync()
        .map_err(|e| AgentError::Connection(format!("创建 TUN 设备失败：{e}")))?;
    let name = device
        .name()
        .map_err(|e| AgentError::Connection(format!("读取 TUN 设备名失败：{e}")))?;
    let if_index = device
        .if_index()
        .map_err(|e| AgentError::Connection(format!("读取 TUN if_index 失败：{e}")))?;

    let dns_capture_target = tun_ipv4_peer(ipv4, ipv4_prefix).unwrap_or(ipv4);
    Ok(PreparedTun {
        device,
        name: name.clone(),
        if_index,
        route_recovery: PersistedRouteRecovery {
            request: request.clone(),
            actual_name: name,
            tun_if_index: if_index,
            tun_ipv4: ipv4,
            dns_capture_target,
            proxy_ips,
        },
    })
}

pub(super) fn handle_client(
    stream: &mut UnixStream,
    leases: &mut LeaseRegistry,
    owner_pid: u32,
) -> Result<()> {
    let request: TunHelperRequest = read_frame(stream)?;
    debug!("收到 helper 请求：{request:?}");
    match request {
        TunHelperRequest::Ping => send_response(stream, &TunHelperResponse::Pong, None)?,
        TunHelperRequest::GetHelperInfo => send_response(
            stream,
            &TunHelperResponse::HelperInfo {
                protocol_version: TUN_HELPER_PROTOCOL_VERSION,
            },
            None,
        )?,
        TunHelperRequest::CleanupStale {
            route_state_file: _,
            dns_state_file: _,
        } => {
            // CleanupStale is also the installer/update hand-off. Never tear
            // down a lease still owned by a live Agent behind its back.
            leases.cleanup_orphans_for("cleanup_stale")?;
            let (route_state_file, dns_state_file) = leases.trusted_state_paths();
            let route_state_file = route_state_file.to_string_lossy().into_owned();
            let dns_state_file = dns_state_file.to_string_lossy().into_owned();
            cleanup_lease_artifacts(Some(&route_state_file), Some(&dns_state_file), None)?;
            send_response(stream, &TunHelperResponse::Ok, None)?;
        }
        TunHelperRequest::RefreshMacosScopedDefaultBypass => {
            refresh_macos_scoped_default_bypass();
            send_response(stream, &TunHelperResponse::Ok, None)?;
        }
        TunHelperRequest::StopTun {
            lease_id,
            route_state_file,
            dns_state_file,
        } => {
            let owner_start_time = process_start_time(owner_pid).ok_or_else(|| {
                anyhow::anyhow!(
                    "无法读取 StopTun peer_pid={owner_pid} 的进程启动时间，拒绝未绑定 owner identity 的清理"
                )
            })?;
            if leases.stop_owned(
                &lease_id,
                route_state_file,
                dns_state_file,
                owner_pid,
                owner_start_time,
            )? {
                info!("已清理 TUN helper lease：{lease_id}");
            } else {
                debug!("TUN helper lease 不存在或已清理：{lease_id}");
            }
            send_response(stream, &TunHelperResponse::Ok, None)?;
        }
        TunHelperRequest::StartTun(request) => {
            // Split routes and the PF anchor are process-global. Never let a
            // second client silently dismantle a lease still owned by another
            // live Agent.
            leases.cleanup_orphans_for("start_tun")?;
            let request = leases.confine_start_request(request)?;
            let owner_start_time = process_start_time(owner_pid).ok_or_else(|| {
                anyhow::anyhow!(
                    "无法读取 helper 客户端 PID={owner_pid} 的进程启动时间，拒绝创建无法抵御 PID 复用的 TUN lease"
                )
            })?;
            let prepared = prepare_tun(&request).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let lease_id = next_lease_id();
            let PreparedTun {
                device,
                name,
                if_index,
                route_recovery,
            } = prepared;
            let metadata = PersistedTunLease {
                lease_id: lease_id.clone(),
                owner_pid,
                owner_start_time: Some(owner_start_time),
                cleanup_requested: false,
                route_state_file: request.route_state_file.clone(),
                dns_state_file: request.dns_state_file.clone(),
                pf_enable_token: None,
                route_recovery: Some(route_recovery),
            };
            leases.stage(metadata.clone())?;
            let route_guard = {
                let mut persist_pf_token = |token: Option<&str>| {
                    leases
                        .set_pf_enable_token(&lease_id, token.map(ToOwned::to_owned))
                        .map_err(|err| AgentError::Connection(err.to_string()))
                };
                restore_route_guard(&metadata, &mut persist_pf_token)
                    .map_err(|err| anyhow::anyhow!(err.to_string()))
            };
            let route_guard = match route_guard {
                Ok(route_guard) => route_guard,
                Err(err) => {
                    let cleanup_result = leases.stop(&lease_id, None, None);
                    if let Err(cleanup_err) = cleanup_result {
                        return Err(anyhow::anyhow!(
                            "安装 TUN 路由/PF 失败：{err}；回滚也失败：{cleanup_err}"
                        ));
                    }
                    return Err(err);
                }
            };
            if let Err(err) = leases.attach_guard(&lease_id, Some(route_guard)) {
                if let Err(cleanup_err) = leases.stop(&lease_id, None, None) {
                    return Err(anyhow::anyhow!(
                        "激活 TUN route guard 失败：{err}；回滚也失败：{cleanup_err}"
                    ));
                }
                return Err(err);
            }

            let fd = device.into_raw_fd();
            let response = TunHelperResponse::TunStarted(TunStartedResponse {
                lease_id: lease_id.clone(),
                name,
                if_index,
            });
            let send_result = send_response(stream, &response, Some(fd));
            unsafe {
                libc::close(fd);
            }
            if let Err(send_err) = send_result {
                if let Err(cleanup_err) = leases.stop(&lease_id, None, None) {
                    return Err(anyhow::anyhow!(
                        "返回 TUN fd 失败：{send_err}；回滚也失败：{cleanup_err}"
                    ));
                }
                return Err(send_err);
            }
            info!("已创建 TUN helper lease：{lease_id}");
        }
    }
    Ok(())
}

pub(super) fn next_lease_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = common::current_timestamp();
    format!("{now}-{counter}")
}
