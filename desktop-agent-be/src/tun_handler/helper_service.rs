use super::device::{tun_ipv4_destination, tun_ipv4_interface_prefix, tun_ipv4_peer};
use super::dns::warn_legacy_dns_state;
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
pub const HELPER_LEASE_STATE_VERSION: u8 = 1;
const HELPER_LEASE_STATE_SUFFIX: &str = ".leases.json";
static HELPER_LEASE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[allow(dead_code)]
pub struct TunSystemLease {
    pub route_guard: Option<RouteGuard>,
    pub metadata: PersistedTunLease,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedTunLease {
    pub lease_id: String,
    pub owner_pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_start_time: Option<ProcessStartTime>,
    #[serde(default)]
    pub cleanup_requested: bool,
    pub route_state_file: Option<String>,
    pub dns_state_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pf_enable_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_recovery: Option<PersistedRouteRecovery>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStartTime {
    pub unix_secs: u64,
    pub micros: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedRouteRecovery {
    pub request: TunStartRequest,
    pub actual_name: String,
    pub tun_if_index: u32,
    pub tun_ipv4: Ipv4Addr,
    pub dns_capture_target: Ipv4Addr,
    pub proxy_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedLeaseState {
    pub version: u8,
    pub leases: Vec<PersistedTunLease>,
}

impl PersistedTunLease {
    pub fn clear_runtime_proxy_addresses(&mut self) {
        if let Some(recovery) = self.route_recovery.as_mut() {
            recovery.request.proxy_addrs.clear();
        }
    }
}

pub struct LeaseRegistry {
    pub state_path: PathBuf,
    pub leases: HashMap<String, TunSystemLease>,
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
    warn_legacy_dns_state(dns_state_file);
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
pub use state::*;
