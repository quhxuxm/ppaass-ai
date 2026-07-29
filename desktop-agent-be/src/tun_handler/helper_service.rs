use super::device::{tun_ipv4_destination, tun_ipv4_interface_prefix, tun_ipv4_peer};
use super::dns::DnsGuard;
use super::network;
use super::route::{
    RouteGuard, RouteGuardInstall, cleanup_macos_pf_dns_capture_with_token,
    cleanup_stale_routes_checked, refresh_macos_scoped_default_bypass, resolve_proxy_ips_checked,
};
use crate::error::{AgentError, Result as AgentResult};
use anyhow::{Context, Result};
use common::tun_control::{
    DEFAULT_TUN_HELPER_SOCKET_PATH, TUN_HELPER_PROTOCOL_VERSION, TunHelperRequest,
    TunHelperResponse, TunStartRequest, TunStartedResponse, tun_helper_dns_state_path,
    tun_helper_route_state_path,
};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::{self, File, OpenOptions};
use std::io::{IoSlice, Read, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, error, info, warn};
use tun_rs::DeviceBuilder;

const HELPER_CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(20);
const HELPER_LEASE_STATE_VERSION: u8 = 1;
const HELPER_LEASE_STATE_SUFFIX: &str = ".leases.json";
static HELPER_LEASE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[allow(dead_code)]
struct TunSystemLease {
    route_guard: Option<RouteGuard>,
    metadata: PersistedTunLease,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedTunLease {
    lease_id: String,
    owner_pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_start_time: Option<ProcessStartTime>,
    #[serde(default)]
    cleanup_requested: bool,
    route_state_file: Option<String>,
    dns_state_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pf_enable_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route_recovery: Option<PersistedRouteRecovery>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ProcessStartTime {
    unix_secs: u64,
    micros: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRouteRecovery {
    request: TunStartRequest,
    actual_name: String,
    tun_if_index: u32,
    tun_ipv4: Ipv4Addr,
    dns_capture_target: Ipv4Addr,
    proxy_ips: Vec<IpAddr>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedLeaseState {
    version: u8,
    leases: Vec<PersistedTunLease>,
}

struct LeaseRegistry {
    state_path: PathBuf,
    leases: HashMap<String, TunSystemLease>,
}

struct PreparedTun {
    device: tun_rs::SyncDevice,
    name: String,
    if_index: u32,
    route_recovery: PersistedRouteRecovery,
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
    if !socket_path.is_absolute() {
        anyhow::bail!(
            "TUN helper socket 必须使用绝对路径，拒绝依赖 root 进程当前目录：{}",
            socket_path.display()
        );
    }
    prepare_socket_path(&socket_path)?;
    let mut leases = LeaseRegistry::recover(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("绑定 helper socket 失败：{}", socket_path.display()))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o666))
        .with_context(|| format!("设置 helper socket 权限失败：{}", socket_path.display()))?;
    info!("PPAASS TUN helper 已监听：{}", socket_path.display());

    for incoming in listener.incoming() {
        match incoming {
            Ok(mut stream) => {
                if let Err(err) = configure_client_timeouts(&stream) {
                    warn!("设置 helper 客户端 IO 超时失败：{err}");
                }
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
                let owner_pid = match peer_pid(&stream) {
                    Ok(pid) => pid,
                    Err(err) => {
                        warn!("无法读取 helper 客户端 PID；StartTun 将被拒绝：{err}");
                        0
                    }
                };
                match catch_unwind(AssertUnwindSafe(|| {
                    handle_client(&mut stream, &mut leases, owner_pid)
                })) {
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

fn configure_client_timeouts(stream: &UnixStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(HELPER_CLIENT_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(HELPER_CLIENT_IO_TIMEOUT))?;
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

fn cleanup_stale(route_state_file: Option<&str>, dns_state_file: Option<&str>) -> Result<()> {
    cleanup_stale_routes_checked(route_state_file)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    debug!("TUN helper 不会修改系统 DNS；仅检查并恢复旧版本遗留的 DNS 状态");
    let _ = DnsGuard::install(false, None, 0, Ipv4Addr::UNSPECIFIED, dns_state_file);
    Ok(())
}

fn cleanup_lease_artifacts(
    route_state_file: Option<&str>,
    dns_state_file: Option<&str>,
    pf_enable_token: Option<&str>,
) -> Result<()> {
    // Flush the global anchor and release the exact token captured by `pfctl
    // -E` before removing recovered route state. The caller retains durable
    // metadata on any failure so a later helper can retry both operations.
    cleanup_macos_pf_dns_capture_with_token(pf_enable_token)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    cleanup_stale(route_state_file, dns_state_file)
}

mod client;
mod lease_recovery;
mod lease_registry;
mod socket_io;
mod state;

use client::handle_client;
use socket_io::*;
use state::*;

#[cfg(test)]
mod tests;
