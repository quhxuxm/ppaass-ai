use super::device::{tun_ipv4_destination, tun_ipv4_interface_prefix, tun_ipv4_peer};
use super::dns::DnsGuard;
use super::network;
use super::route::{RouteGuard, cleanup_stale_routes, resolve_proxy_ips};
use crate::error::{AgentError, Result as AgentResult};
use anyhow::{Context, Result};
use common::tun_control::{
    DEFAULT_TUN_HELPER_SOCKET_PATH, TunHelperRequest, TunHelperResponse, TunStartRequest,
    TunStartedResponse,
};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use std::collections::HashMap;
use std::fs;
use std::io::{IoSlice, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, error, info, warn};
use tun_rs::DeviceBuilder;

#[allow(dead_code)]
struct TunSystemLease {
    route_guard: Option<RouteGuard>,
}

struct PreparedTun {
    device: tun_rs::SyncDevice,
    name: String,
    if_index: u32,
    lease: TunSystemLease,
}

pub(crate) fn run(
    socket: Option<&str>,
    allowed_uid: Option<u32>,
    log_level: Option<&str>,
) -> Result<()> {
    init_tracing(log_level.unwrap_or("info"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("创建 TUN helper Tokio runtime 失败")?;
    let _runtime_guard = runtime.enter();

    if effective_uid() != 0 {
        warn!("desktop-agent TUN helper 模式当前不是 root，TUN 创建和路由修改通常会失败");
    }
    if allowed_uid.is_none() {
        warn!("未设置 --tun-helper-allowed-uid；本机任意用户都可以连接 helper socket");
    }

    let socket_path = PathBuf::from(socket.unwrap_or(DEFAULT_TUN_HELPER_SOCKET_PATH));
    prepare_socket_path(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("绑定 helper socket 失败：{}", socket_path.display()))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o666))
        .with_context(|| format!("设置 helper socket 权限失败：{}", socket_path.display()))?;
    info!("PPAASS TUN helper 已监听：{}", socket_path.display());

    let mut leases: HashMap<String, TunSystemLease> = HashMap::new();
    for incoming in listener.incoming() {
        match incoming {
            Ok(mut stream) => {
                if let Err(err) = authorize_peer(&stream, allowed_uid) {
                    warn!("拒绝 helper 客户端：{err}");
                    let _ = send_response(
                        &stream,
                        &TunHelperResponse::Error {
                            message: err.to_string(),
                        },
                        None,
                    );
                    continue;
                }
                match catch_unwind(AssertUnwindSafe(|| handle_client(&mut stream, &mut leases))) {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        error!("处理 helper 请求失败：{err}");
                        let _ = send_response(
                            &stream,
                            &TunHelperResponse::Error {
                                message: err.to_string(),
                            },
                            None,
                        );
                    }
                    Err(payload) => {
                        let message = panic_payload_message(payload.as_ref());
                        error!("处理 helper 请求时 panic：{message}");
                        let _ = send_response(
                            &stream,
                            &TunHelperResponse::Error {
                                message: format!("TUN helper panic：{message}"),
                            },
                            None,
                        );
                    }
                }
            }
            Err(err) => warn!("接受 helper 连接失败：{err}"),
        }
    }

    Ok(())
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

fn cleanup_stale(route_state_file: Option<&str>, dns_state_file: Option<&str>) {
    cleanup_stale_routes(route_state_file);
    debug!("TUN helper 不会修改系统 DNS；仅检查并恢复旧版本遗留的 DNS 状态");
    let _ = DnsGuard::install(false, None, 0, Ipv4Addr::UNSPECIFIED, dns_state_file);
}

fn prepare_tun(request: &TunStartRequest) -> AgentResult<PreparedTun> {
    let (ipv4, ipv4_prefix) = network::parse_cidr_v4(&request.ipv4)?;
    let ipv6_config = request
        .ipv6
        .as_deref()
        .map(network::parse_cidr_v6)
        .transpose()?;

    cleanup_stale(
        request.route_state_file.as_deref(),
        request.dns_state_file.as_deref(),
    );

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

    let proxy_ips = resolve_proxy_ips(&request.proxy_addrs);
    let dns_capture_target = tun_ipv4_peer(ipv4, ipv4_prefix).unwrap_or(ipv4);
    let route_guard = match RouteGuard::install(
        if_index,
        ipv4,
        dns_capture_target,
        request.ipv6.as_deref(),
        request.route_state_file.as_deref(),
        &proxy_ips,
        request.proxy_dns,
    ) {
        Ok(guard) => Some(guard),
        Err(e) => {
            tracing::warn!("helper 安装 TUN 路由失败：{e}");
            None
        }
    };

    Ok(PreparedTun {
        device,
        name,
        if_index,
        lease: TunSystemLease { route_guard },
    })
}

fn handle_client(
    stream: &mut UnixStream,
    leases: &mut HashMap<String, TunSystemLease>,
) -> Result<()> {
    let request: TunHelperRequest = read_frame(stream)?;
    debug!("收到 helper 请求：{request:?}");
    match request {
        TunHelperRequest::Ping => send_response(stream, &TunHelperResponse::Pong, None)?,
        TunHelperRequest::CleanupStale {
            route_state_file,
            dns_state_file,
        } => {
            cleanup_stale(route_state_file.as_deref(), dns_state_file.as_deref());
            send_response(stream, &TunHelperResponse::Ok, None)?;
        }
        TunHelperRequest::StopTun { lease_id } => {
            if leases.remove(&lease_id).is_some() {
                info!("已清理 TUN helper lease：{lease_id}");
            } else {
                debug!("TUN helper lease 不存在或已清理：{lease_id}");
            }
            send_response(stream, &TunHelperResponse::Ok, None)?;
        }
        TunHelperRequest::StartTun(request) => {
            let prepared = prepare_tun(&request).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let lease_id = next_lease_id();
            let fd = prepared.device.into_raw_fd();
            let response = TunHelperResponse::TunStarted(TunStartedResponse {
                lease_id: lease_id.clone(),
                name: prepared.name,
                if_index: prepared.if_index,
            });
            let send_result = send_response(stream, &response, Some(fd));
            unsafe {
                libc::close(fd);
            }
            send_result?;
            leases.insert(lease_id.clone(), prepared.lease);
            info!("已创建 TUN helper lease：{lease_id}");
        }
    }
    Ok(())
}

fn next_lease_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = common::current_timestamp();
    format!("{now}-{counter}")
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("创建 helper socket 目录失败：{}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("设置 helper socket 目录权限失败：{}", parent.display()))?;
    }
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("删除旧 helper socket 失败：{}", path.display()));
        }
    }
    Ok(())
}

fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        anyhow::bail!("helper 请求过大：{len} bytes");
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

fn send_response(
    stream: &UnixStream,
    response: &TunHelperResponse,
    fd: Option<RawFd>,
) -> Result<()> {
    send_fd_marker(stream, fd)?;

    let payload = serde_json::to_vec(response)?;
    let len: u32 = payload.len().try_into().context("helper 响应过大")?;
    let mut stream = stream;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&payload)?;
    Ok(())
}

fn send_fd_marker(stream: &UnixStream, fd: Option<RawFd>) -> Result<()> {
    let marker = [1u8];
    let iov = [IoSlice::new(&marker)];
    if let Some(fd) = fd {
        let fds = [fd];
        sendmsg::<()>(
            stream.as_raw_fd(),
            &iov,
            &[ControlMessage::ScmRights(&fds)],
            MsgFlags::empty(),
            None,
        )?;
    } else {
        sendmsg::<()>(stream.as_raw_fd(), &iov, &[], MsgFlags::empty(), None)?;
    }
    Ok(())
}

fn authorize_peer(stream: &UnixStream, allowed_uid: Option<u32>) -> Result<()> {
    let Some(allowed_uid) = allowed_uid else {
        return Ok(());
    };
    let uid = peer_uid(stream)?;
    if uid == 0 || uid == allowed_uid {
        return Ok(());
    }
    anyhow::bail!("uid={uid} 无权使用 helper，允许 uid={allowed_uid}");
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    Ok(getsockopt(stream, PeerCredentials)?.uid())
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerCred};
    Ok(getsockopt(stream, LocalPeerCred)?.uid())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_uid(_stream: &UnixStream) -> Result<u32> {
    anyhow::bail!("当前 Unix 平台暂未实现 helper peer credential 校验")
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn init_tracing(log_level: &str) {
    let filter = tracing_subscriber::EnvFilter::new(log_level);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
