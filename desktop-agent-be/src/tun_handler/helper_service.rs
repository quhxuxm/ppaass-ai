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

impl LeaseRegistry {
    fn recover(socket_path: &Path) -> Result<Self> {
        let state_path = helper_lease_state_path(socket_path);
        let persisted = load_persisted_leases(&state_path)?;
        let trusted_route_state = tun_helper_route_state_path(socket_path);
        let trusted_dns_state = tun_helper_dns_state_path(socket_path);
        for metadata in &persisted {
            validate_persisted_lease_state_paths(
                metadata,
                &trusted_route_state,
                &trusted_dns_state,
            )?;
        }
        let leases = persisted
            .into_iter()
            .map(|metadata| {
                (
                    metadata.lease_id.clone(),
                    TunSystemLease {
                        route_guard: None,
                        metadata,
                    },
                )
            })
            .collect();
        let mut registry = Self { state_path, leases };
        if registry.leases.len() > 1 {
            anyhow::bail!(
                "发现 {} 个持久 TUN helper lease；PF anchor 是全局单例，拒绝在所有权不明确时恢复或清理",
                registry.leases.len()
            );
        }
        let lease_ids = registry.leases.keys().cloned().collect::<Vec<_>>();

        for lease_id in lease_ids {
            let metadata = registry
                .leases
                .get(&lease_id)
                .expect("persisted lease disappeared during recovery")
                .metadata
                .clone();
            if lease_owner_is_alive(&metadata) {
                if let Err(err) = registry.release_recovered_pf_token(&lease_id) {
                    anyhow::bail!(
                        "恢复存活 Agent 的 TUN helper lease={} 前释放旧 PF token 失败：{}；保留恢复元数据并拒绝启动",
                        lease_id,
                        err
                    );
                }
                let refreshed_metadata = registry
                    .leases
                    .get(&lease_id)
                    .expect("lease disappeared after recovered PF cleanup")
                    .metadata
                    .clone();
                let route_guard = {
                    let mut persist_pf_token = |token: Option<&str>| {
                        registry
                            .set_pf_enable_token(&lease_id, token.map(ToOwned::to_owned))
                            .map_err(|err| AgentError::Connection(err.to_string()))
                    };
                    restore_route_guard(&refreshed_metadata, &mut persist_pf_token)
                };
                match route_guard {
                    Ok(route_guard) => {
                        registry.attach_guard(&lease_id, Some(route_guard))?;
                        info!(
                            "已完整恢复 TUN helper lease={}：owner_pid={}，路由、PF DNS 捕获及 enable token 均已重建",
                            lease_id, metadata.owner_pid
                        );
                        continue;
                    }
                    Err(err) => {
                        error!(
                            "恢复存活 Agent 的 TUN helper lease={} 失败，将撤销遗留 TUN 网络状态：{}",
                            lease_id, err
                        );
                    }
                }
            } else if metadata.cleanup_requested {
                warn!(
                    "发现尚未完成清理的 TUN helper lease={}，准备继续恢复系统网络",
                    lease_id
                );
            } else {
                warn!(
                    "发现 owner_pid={} 进程实例已退出、已复用或缺少启动时间的 TUN helper lease={}，准备恢复系统网络",
                    metadata.owner_pid, lease_id
                );
            }

            if let Err(cleanup_error) = registry.stop(&lease_id, None, None) {
                anyhow::bail!(
                    "TUN helper lease={} 恢复失败且 PF/路由清理失败：{}；保留恢复元数据并拒绝启动",
                    lease_id,
                    cleanup_error
                );
            }
            info!("已清理异常退出或恢复失败的 TUN helper lease={lease_id}");
        }

        registry.persist()?;
        if !registry.leases.is_empty() {
            info!(
                "已恢复 {} 个 TUN helper lease 的完整路由/PF guard",
                registry.leases.len()
            );
        }
        Ok(registry)
    }

    fn trusted_state_paths(&self) -> (PathBuf, PathBuf) {
        (
            tun_helper_route_state_path(&self.state_path),
            tun_helper_dns_state_path(&self.state_path),
        )
    }

    fn confine_start_request(&self, mut request: TunStartRequest) -> Result<TunStartRequest> {
        let (route_state, dns_state) = self.trusted_state_paths();
        request.route_state_file = Some(confine_requested_state_path(
            "route",
            request.route_state_file.as_deref(),
            &route_state,
        )?);
        request.dns_state_file = Some(confine_requested_state_path(
            "dns",
            request.dns_state_file.as_deref(),
            &dns_state,
        )?);
        Ok(request)
    }

    fn persist(&self) -> Result<()> {
        if self.leases.is_empty() {
            match fs::remove_file(&self.state_path) {
                Ok(()) => {
                    sync_parent_directory(&self.state_path)?;
                    debug!(
                        "已删除空的 TUN helper lease 状态文件：{}",
                        self.state_path.display()
                    );
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!(
                            "删除 TUN helper lease 状态文件失败：{}",
                            self.state_path.display()
                        )
                    });
                }
            }
            return Ok(());
        }

        let mut leases = self
            .leases
            .values()
            .map(|lease| lease.metadata.clone())
            .collect::<Vec<_>>();
        leases.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        persist_lease_state(
            &self.state_path,
            &PersistedLeaseState {
                version: HELPER_LEASE_STATE_VERSION,
                leases,
            },
        )
    }

    fn stage(&mut self, metadata: PersistedTunLease) -> Result<()> {
        let lease_id = metadata.lease_id.clone();
        self.leases.insert(
            lease_id.clone(),
            TunSystemLease {
                route_guard: None,
                metadata,
            },
        );
        if let Err(err) = self.persist() {
            self.leases.remove(&lease_id);
            return Err(err);
        }
        Ok(())
    }

    fn stage_before<T>(
        &mut self,
        metadata: PersistedTunLease,
        install: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.stage(metadata)?;
        install()
    }

    fn attach_guard(&mut self, lease_id: &str, route_guard: Option<RouteGuard>) -> Result<()> {
        let Some(staged) = self.leases.get_mut(lease_id) else {
            anyhow::bail!("待激活的 TUN helper lease 不存在：{lease_id}");
        };
        staged.route_guard = route_guard;
        Ok(())
    }

    fn set_pf_enable_token(&mut self, lease_id: &str, token: Option<String>) -> Result<()> {
        let lease = self
            .leases
            .get_mut(lease_id)
            .with_context(|| format!("更新 PF token 时 TUN helper lease 不存在：{lease_id}"))?;
        lease.metadata.pf_enable_token = token;
        if let Err(err) = self.persist() {
            // Keep the new token in memory. The install error path immediately
            // retries cleanup through this registry; rolling back here would
            // lose the only token capable of undoing a failed `pfctl -E`.
            return Err(err.context(format!(
                "持久化 TUN helper lease={lease_id} 的 PF enable token 失败"
            )));
        }
        Ok(())
    }

    fn release_recovered_pf_token(&mut self, lease_id: &str) -> Result<()> {
        let token = self
            .leases
            .get(lease_id)
            .with_context(|| format!("释放恢复 PF token 时 lease 不存在：{lease_id}"))?
            .metadata
            .pf_enable_token
            .clone();
        cleanup_macos_pf_dns_capture_with_token(token.as_deref())
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        self.set_pf_enable_token(lease_id, None)
    }

    fn stop_owned(
        &mut self,
        lease_id: &str,
        route_state_hint: Option<String>,
        dns_state_hint: Option<String>,
        owner_pid: u32,
        owner_start_time: ProcessStartTime,
    ) -> Result<bool> {
        self.stop_owned_with_artifact_cleanup(
            lease_id,
            route_state_hint,
            dns_state_hint,
            owner_pid,
            owner_start_time,
            cleanup_lease_artifacts,
        )
    }

    fn stop_owned_with_artifact_cleanup(
        &mut self,
        lease_id: &str,
        route_state_hint: Option<String>,
        dns_state_hint: Option<String>,
        owner_pid: u32,
        owner_start_time: ProcessStartTime,
        cleanup_artifacts: impl FnMut(Option<&str>, Option<&str>, Option<&str>) -> Result<()>,
    ) -> Result<bool> {
        let Some(lease) = self.leases.get(lease_id) else {
            // Durable lease metadata is authoritative. A duplicate/unknown
            // StopTun is idempotent and must never use untrusted hints to
            // flush the process-global PF anchor or touch another lease.
            debug!(
                "忽略未知 TUN helper lease 的 StopTun：lease={} owner_pid={}",
                lease_id, owner_pid
            );
            return Ok(false);
        };
        if lease.metadata.owner_pid != owner_pid
            || lease.metadata.owner_start_time != Some(owner_start_time)
        {
            anyhow::bail!(
                "拒绝 StopTun：lease={} 归属 owner_pid={} start_time={:?}，当前 peer_pid={} start_time={:?}",
                lease_id,
                lease.metadata.owner_pid,
                lease.metadata.owner_start_time,
                owner_pid,
                owner_start_time
            );
        }
        self.stop_with_artifact_cleanup(
            lease_id,
            route_state_hint,
            dns_state_hint,
            cleanup_artifacts,
        )
    }

    fn stop(
        &mut self,
        lease_id: &str,
        route_state_hint: Option<String>,
        dns_state_hint: Option<String>,
    ) -> Result<bool> {
        self.stop_with_artifact_cleanup(
            lease_id,
            route_state_hint,
            dns_state_hint,
            cleanup_lease_artifacts,
        )
    }

    fn stop_with_artifact_cleanup(
        &mut self,
        lease_id: &str,
        _route_state_hint: Option<String>,
        _dns_state_hint: Option<String>,
        mut cleanup_artifacts: impl FnMut(Option<&str>, Option<&str>, Option<&str>) -> Result<()>,
    ) -> Result<bool> {
        let Some(metadata) = self
            .leases
            .get(lease_id)
            .map(|lease| lease.metadata.clone())
        else {
            return Ok(false);
        };

        let (route_state_file, dns_state_file) = self.safe_recovery_paths(lease_id, &metadata);
        let mut retry_metadata = metadata;
        retry_metadata.cleanup_requested = true;
        retry_metadata.route_state_file = route_state_file.clone();
        retry_metadata.dns_state_file = dns_state_file.clone();

        // Persist "cleanup requested" before touching PF/routes. The original
        // owner identity remains available for an authenticated retry, while a
        // restarted helper sees this as recovery work rather than a live lease.
        self.leases
            .get_mut(lease_id)
            .expect("stop target disappeared before staging cleanup")
            .metadata = retry_metadata;
        self.persist()?;

        let cleanup_result = {
            let lease = self
                .leases
                .get_mut(lease_id)
                .expect("stop metadata was staged before cleanup");
            if let Some(route_guard) = lease.route_guard.as_mut() {
                route_guard
                    .cleanup()
                    .map_err(|err| anyhow::anyhow!(err.to_string()))
            } else {
                cleanup_artifacts(
                    route_state_file.as_deref(),
                    dns_state_file.as_deref(),
                    lease.metadata.pf_enable_token.as_deref(),
                )
            }
        };
        if let Err(cleanup_error) = cleanup_result {
            anyhow::bail!(
                "TUN helper lease={} PF/路由清理失败：{}；已保留恢复元数据，请重试停止",
                lease_id,
                cleanup_error
            );
        }

        if lease_state_files_remain_at(route_state_file.as_deref(), dns_state_file.as_deref()) {
            anyhow::bail!(
                "TUN helper lease={} 仍有状态文件未清理；已保留恢复元数据，请重试停止",
                lease_id
            );
        }

        let cleaned_lease = self
            .leases
            .remove(lease_id)
            .expect("stop metadata disappeared after cleanup");
        if let Err(persist_error) = self.persist() {
            self.leases.insert(lease_id.to_string(), cleaned_lease);
            return match self.persist() {
                Ok(()) => Err(persist_error.context(format!(
                    "TUN helper lease={lease_id} 已完成网络清理，但无法持久提交 lease 删除；已恢复重试元数据"
                ))),
                Err(restore_error) => Err(anyhow::anyhow!(
                    "TUN helper lease={lease_id} 已完成网络清理，但提交 lease 删除失败：{persist_error}；恢复重试元数据也失败：{restore_error}"
                )),
            };
        }
        Ok(true)
    }

    fn stop_all(&mut self) -> Result<()> {
        let lease_ids = self.leases.keys().cloned().collect::<Vec<_>>();
        for lease_id in lease_ids {
            self.stop(&lease_id, None, None)?;
        }
        if !self.leases.is_empty() {
            anyhow::bail!(
                "仍有 {} 个旧 TUN helper lease 未能清理，拒绝覆盖其恢复状态",
                self.leases.len()
            );
        }
        Ok(())
    }

    fn cleanup_orphans_for(&mut self, operation: &str) -> Result<()> {
        let live_lease_ids = self
            .leases
            .values()
            .filter(|lease| lease_owner_is_alive(&lease.metadata))
            .map(|lease| lease.metadata.lease_id.as_str())
            .collect::<Vec<_>>();
        if !live_lease_ids.is_empty() {
            anyhow::bail!(
                "TUN helper busy：操作={}，仍被 Agent 持有的 lease={}；请先停止原 TUN",
                operation,
                live_lease_ids.join(","),
            );
        }
        self.stop_all()
    }

    fn route_state_owned_by_another(&self, lease_id: &str, path: &str) -> bool {
        self.leases.iter().any(|(active_id, lease)| {
            active_id != lease_id && lease.metadata.route_state_file.as_deref() == Some(path)
        })
    }

    fn dns_state_owned_by_another(&self, lease_id: &str, path: &str) -> bool {
        self.leases.iter().any(|(active_id, lease)| {
            active_id != lease_id && lease.metadata.dns_state_file.as_deref() == Some(path)
        })
    }

    fn safe_recovery_paths(
        &self,
        lease_id: &str,
        metadata: &PersistedTunLease,
    ) -> (Option<String>, Option<String>) {
        let route_state_file = metadata
            .route_state_file
            .clone()
            .filter(|path| !self.route_state_owned_by_another(lease_id, path));
        let dns_state_file = metadata
            .dns_state_file
            .clone()
            .filter(|path| !self.dns_state_owned_by_another(lease_id, path));
        (route_state_file, dns_state_file)
    }
}

fn helper_lease_state_path(socket_path: &Path) -> PathBuf {
    let mut file_name = socket_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("tun-helper.sock"))
        .to_os_string();
    file_name.push(HELPER_LEASE_STATE_SUFFIX);
    socket_path.with_file_name(file_name)
}

fn confine_requested_state_path(
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

fn validate_persisted_lease_state_paths(
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

fn load_persisted_leases(path: &Path) -> Result<Vec<PersistedTunLease>> {
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

fn persist_lease_state(path: &Path, state: &PersistedLeaseState) -> Result<()> {
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

fn sync_parent_directory(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)
        .with_context(|| format!("打开 helper lease 状态目录失败：{}", parent.display()))?
        .sync_all()
        .with_context(|| format!("同步 helper lease 状态目录失败：{}", parent.display()))
}

fn lease_owner_is_alive(metadata: &PersistedTunLease) -> bool {
    if metadata.cleanup_requested {
        return false;
    }
    let Some(expected_start_time) = metadata.owner_start_time else {
        return false;
    };
    process_start_time(metadata.owner_pid) == Some(expected_start_time)
}

fn process_start_time(pid: u32) -> Option<ProcessStartTime> {
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

fn lease_state_files_remain(metadata: &PersistedTunLease) -> bool {
    lease_state_files_remain_at(
        metadata.route_state_file.as_deref(),
        metadata.dns_state_file.as_deref(),
    )
}

fn lease_state_files_remain_at(
    route_state_file: Option<&str>,
    dns_state_file: Option<&str>,
) -> bool {
    [route_state_file, dns_state_file]
        .into_iter()
        .flatten()
        .any(|path| !path.trim().is_empty() && Path::new(path).exists())
}

fn restore_route_guard(
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

fn interface_name_for_index(if_index: u32) -> Option<String> {
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

fn prepare_tun(request: &TunStartRequest) -> AgentResult<PreparedTun> {
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

fn handle_client(
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

fn next_lease_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = common::current_timestamp();
    format!("{now}-{counter}")
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        match fs::symlink_metadata(parent) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    anyhow::bail!(
                        "TUN helper socket 目录必须是实际目录，拒绝符号链接或非目录：{}",
                        parent.display()
                    );
                }
                if effective_uid() == 0 && metadata.uid() != 0 {
                    anyhow::bail!(
                        "TUN helper socket 目录不是 root 所有，拒绝在不受信任目录运行：{} uid={}",
                        parent.display(),
                        metadata.uid()
                    );
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(parent).with_context(|| {
                    format!("创建 helper socket 目录失败：{}", parent.display())
                })?;
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("检查 helper socket 目录失败：{}", parent.display()));
            }
        }
        let metadata = fs::metadata(parent)
            .with_context(|| format!("读取 helper socket 目录失败：{}", parent.display()))?;
        if effective_uid() == 0 && metadata.uid() != 0 {
            anyhow::bail!(
                "TUN helper socket 目录不是 root 所有，拒绝在不受信任目录运行：{} uid={}",
                parent.display(),
                metadata.uid()
            );
        }
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

#[cfg(target_os = "macos")]
fn peer_pid(stream: &UnixStream) -> Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerPid};
    let pid = getsockopt(stream, LocalPeerPid)?;
    u32::try_from(pid).context("helper 客户端 PID 无效")
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn lease(id: &str, owner_pid: u32) -> PersistedTunLease {
        PersistedTunLease {
            lease_id: id.to_string(),
            owner_pid,
            owner_start_time: process_start_time(owner_pid),
            cleanup_requested: false,
            route_state_file: Some(format!("/tmp/{id}-routes.json")),
            dns_state_file: Some(format!("/tmp/{id}-dns.json")),
            pf_enable_token: None,
            route_recovery: None,
        }
    }

    fn route_recovery() -> PersistedRouteRecovery {
        PersistedRouteRecovery {
            request: TunStartRequest {
                name: "ppaass-test".to_string(),
                ipv4: "198.18.0.1/15".to_string(),
                ipv6: None,
                mtu: 1500,
                proxy_addrs: vec!["127.0.0.1:8080".to_string()],
                proxy_dns: true,
                proxy_bind_interface: None,
                route_state_file: Some("/tmp/test-routes.json".to_string()),
                dns_state_file: Some("/tmp/test-dns.json".to_string()),
            },
            actual_name: "utun42".to_string(),
            tun_if_index: 42,
            tun_ipv4: Ipv4Addr::new(198, 18, 0, 1),
            dns_capture_target: Ipv4Addr::new(198, 18, 0, 2),
            proxy_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        }
    }

    fn unique_test_path(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "ppaass-helper-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn persisted_lease_survives_helper_restart_round_trip() {
        let path = unique_test_path("leases.json");
        let mut recoverable = lease("lease-b", 42);
        recoverable.route_recovery = Some(route_recovery());
        let expected = vec![recoverable, lease("lease-a", 41)];
        persist_lease_state(
            &path,
            &PersistedLeaseState {
                version: HELPER_LEASE_STATE_VERSION,
                leases: expected.clone(),
            },
        )
        .unwrap();

        let loaded = load_persisted_leases(&path).unwrap();
        assert_eq!(
            serde_json::to_value(loaded).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn legacy_lease_without_process_start_time_is_readable_but_not_live() {
        let metadata: PersistedTunLease = serde_json::from_str(
            r#"{
                "lease_id":"legacy",
                "owner_pid":42,
                "route_state_file":null,
                "dns_state_file":null
            }"#,
        )
        .unwrap();

        assert_eq!(metadata.owner_start_time, None);
        assert!(!lease_owner_is_alive(&metadata));
    }

    #[test]
    fn lease_owner_identity_rejects_pid_reuse() {
        let pid = std::process::id();
        let current_start_time = process_start_time(pid).expect("current process start time");
        let mut metadata = lease("identity", pid);
        assert!(lease_owner_is_alive(&metadata));

        metadata.owner_start_time = Some(ProcessStartTime {
            unix_secs: current_start_time.unix_secs.saturating_add(1),
            micros: current_start_time.micros,
        });
        assert!(!lease_owner_is_alive(&metadata));
    }

    #[test]
    fn restart_metadata_contains_full_start_request_and_actual_tun_identity() {
        let recovery = route_recovery();
        let value = serde_json::to_value(&recovery).unwrap();

        assert_eq!(value["request"]["ipv4"], "198.18.0.1/15");
        assert_eq!(value["request"]["proxy_dns"], true);
        assert_eq!(value["actual_name"], "utun42");
        assert_eq!(value["tun_if_index"], 42);
        assert_eq!(value["proxy_ips"][0], "127.0.0.1");
    }

    #[test]
    fn start_request_state_paths_are_confined_to_the_helper_directory() {
        let registry = LeaseRegistry {
            state_path: unique_test_path("trusted/helper.sock.leases.json"),
            leases: HashMap::new(),
        };
        let (trusted_route, trusted_dns) = registry.trusted_state_paths();
        let mut request = route_recovery().request;
        request.route_state_file = None;
        request.dns_state_file = Some(String::new());

        let confined = registry.confine_start_request(request).unwrap();

        assert_eq!(
            confined.route_state_file.as_deref(),
            Some(trusted_route.to_string_lossy().as_ref())
        );
        assert_eq!(
            confined.dns_state_file.as_deref(),
            Some(trusted_dns.to_string_lossy().as_ref())
        );

        let mut escaped = route_recovery().request;
        escaped.route_state_file = Some("/etc/ppaass-overwrite.json".to_string());
        let error = registry
            .confine_start_request(escaped)
            .unwrap_err()
            .to_string();
        assert!(error.contains("状态路径越界"));
        assert!(error.contains("/etc/ppaass-overwrite.json"));
    }

    #[test]
    fn persisted_lease_recovery_rejects_top_level_and_nested_untrusted_paths() {
        let socket = Path::new("/var/run/ppaass-ai/tun-helper.sock");
        let trusted_route = tun_helper_route_state_path(socket);
        let trusted_dns = tun_helper_dns_state_path(socket);
        let mut metadata = lease("trusted", std::process::id());
        metadata.route_state_file = Some(trusted_route.to_string_lossy().into_owned());
        metadata.dns_state_file = Some(trusted_dns.to_string_lossy().into_owned());
        let mut recovery = route_recovery();
        recovery.request.route_state_file = metadata.route_state_file.clone();
        recovery.request.dns_state_file = metadata.dns_state_file.clone();
        metadata.route_recovery = Some(recovery);

        validate_persisted_lease_state_paths(&metadata, &trusted_route, &trusted_dns).unwrap();

        metadata.route_state_file = Some("/tmp/untrusted-routes.json".to_string());
        assert!(
            validate_persisted_lease_state_paths(&metadata, &trusted_route, &trusted_dns)
                .unwrap_err()
                .to_string()
                .contains("状态路径不受信任")
        );

        metadata.route_state_file = Some(trusted_route.to_string_lossy().into_owned());
        metadata
            .route_recovery
            .as_mut()
            .unwrap()
            .request
            .dns_state_file = Some("/tmp/untrusted-nested-dns.json".to_string());
        assert!(
            validate_persisted_lease_state_paths(&metadata, &trusted_route, &trusted_dns)
                .unwrap_err()
                .to_string()
                .contains("嵌套路由恢复路径")
        );
    }

    #[test]
    fn lease_metadata_is_durable_before_route_install_starts() {
        let state_path = unique_test_path("stage-before-install.json");
        let observed_path = state_path.clone();
        let metadata = lease("pending", std::process::id());
        let mut registry = LeaseRegistry {
            state_path,
            leases: HashMap::new(),
        };

        registry
            .stage_before(metadata, || {
                let staged = load_persisted_leases(&observed_path)?;
                assert_eq!(staged.len(), 1);
                assert_eq!(staged[0].lease_id, "pending");
                Ok(())
            })
            .unwrap();

        registry.leases.remove("pending");
        registry.persist().unwrap();
        assert!(!observed_path.exists());
    }

    #[test]
    fn cleanup_request_rejects_a_live_agent_lease() {
        let mut metadata = lease("live", std::process::id());
        metadata.route_state_file = None;
        metadata.dns_state_file = None;
        let mut registry = LeaseRegistry {
            state_path: unique_test_path("live-cleanup.json"),
            leases: HashMap::from([(
                metadata.lease_id.clone(),
                TunSystemLease {
                    route_guard: None,
                    metadata,
                },
            )]),
        };

        let error = registry
            .cleanup_orphans_for("upgrade")
            .unwrap_err()
            .to_string();
        assert!(error.contains("helper busy"));
        assert!(registry.leases.contains_key("live"));
    }

    #[test]
    fn cleanup_failure_keeps_durable_retry_metadata() {
        let state_path = unique_test_path("cleanup-retry.json");
        let mut metadata = lease("cleanup-retry", std::process::id());
        metadata.route_state_file = None;
        metadata.dns_state_file = None;
        metadata.pf_enable_token = Some("durable-token".to_string());
        let expected_owner_start_time = metadata.owner_start_time;
        let mut registry = LeaseRegistry {
            state_path: state_path.clone(),
            leases: HashMap::from([(
                metadata.lease_id.clone(),
                TunSystemLease {
                    route_guard: None,
                    metadata,
                },
            )]),
        };

        let error = registry
            .stop_with_artifact_cleanup("cleanup-retry", None, None, |_, _, token| {
                assert_eq!(token, Some("durable-token"));
                anyhow::bail!("injected PF flush failure")
            })
            .unwrap_err()
            .to_string();

        assert!(error.contains("injected PF flush failure"));
        let retained = registry.leases.get("cleanup-retry").unwrap();
        assert_eq!(retained.metadata.owner_pid, std::process::id());
        assert_eq!(
            retained.metadata.owner_start_time,
            expected_owner_start_time
        );
        assert!(retained.metadata.cleanup_requested);
        assert_eq!(
            retained.metadata.pf_enable_token.as_deref(),
            Some("durable-token")
        );
        let persisted = load_persisted_leases(&state_path).unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].lease_id, "cleanup-retry");
        assert_eq!(persisted[0].owner_pid, std::process::id());
        assert_eq!(persisted[0].owner_start_time, expected_owner_start_time);
        assert!(persisted[0].cleanup_requested);
        assert_eq!(
            persisted[0].pf_enable_token.as_deref(),
            Some("durable-token")
        );

        fs::remove_file(state_path).unwrap();
    }

    #[test]
    fn successful_cleanup_durably_removes_lease_metadata() {
        let state_path = unique_test_path("cleanup-success.json");
        let mut metadata = lease("cleanup-success", std::process::id());
        metadata.route_state_file = None;
        metadata.dns_state_file = None;
        let mut registry = LeaseRegistry {
            state_path: state_path.clone(),
            leases: HashMap::from([(
                metadata.lease_id.clone(),
                TunSystemLease {
                    route_guard: None,
                    metadata,
                },
            )]),
        };
        registry.persist().unwrap();

        assert!(
            registry
                .stop_with_artifact_cleanup("cleanup-success", None, None, |_, _, _| Ok(()))
                .unwrap()
        );
        assert!(registry.leases.is_empty());
        assert!(!state_path.exists());
    }

    #[test]
    fn old_stop_request_deserializes_without_recovery_hints() {
        let request: TunHelperRequest =
            serde_json::from_str(r#"{"type":"stop_tun","lease_id":"legacy"}"#).unwrap();

        match request {
            TunHelperRequest::StopTun {
                lease_id,
                route_state_file,
                dns_state_file,
            } => {
                assert_eq!(lease_id, "legacy");
                assert_eq!(route_state_file, None);
                assert_eq!(dns_state_file, None);
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn stop_request_serializes_restart_recovery_hints() {
        let request = TunHelperRequest::StopTun {
            lease_id: "lease-1".to_string(),
            route_state_file: Some("/state/routes.json".to_string()),
            dns_state_file: Some("/state/dns.json".to_string()),
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["type"], "stop_tun");
        assert_eq!(value["lease_id"], "lease-1");
        assert_eq!(value["route_state_file"], "/state/routes.json");
        assert_eq!(value["dns_state_file"], "/state/dns.json");
    }

    #[test]
    fn stale_stop_hint_cannot_clean_a_new_active_lease_path() {
        let active = lease("new-lease", 42);
        let registry = LeaseRegistry {
            state_path: unique_test_path("registry.json"),
            leases: HashMap::from([(
                active.lease_id.clone(),
                TunSystemLease {
                    route_guard: None,
                    metadata: active.clone(),
                },
            )]),
        };

        assert!(registry.route_state_owned_by_another(
            "old-lease",
            active.route_state_file.as_deref().unwrap()
        ));
        assert!(
            registry
                .dns_state_owned_by_another("old-lease", active.dns_state_file.as_deref().unwrap())
        );
    }

    #[test]
    fn unknown_stop_cannot_touch_a_live_lease_or_global_pf_cleanup() {
        let owner_pid = std::process::id();
        let owner_start_time = process_start_time(owner_pid).unwrap();
        let active = lease("live-lease", owner_pid);
        let state_path = unique_test_path("unknown-stop.json");
        let cleanup_called = Cell::new(false);
        let mut registry = LeaseRegistry {
            state_path: state_path.clone(),
            leases: HashMap::from([(
                active.lease_id.clone(),
                TunSystemLease {
                    route_guard: None,
                    metadata: active,
                },
            )]),
        };

        assert!(
            !registry
                .stop_owned_with_artifact_cleanup(
                    "unknown-lease",
                    Some("/tmp/untrusted-routes.json".to_string()),
                    Some("/tmp/untrusted-dns.json".to_string()),
                    owner_pid,
                    owner_start_time,
                    |_, _, _| {
                        cleanup_called.set(true);
                        Ok(())
                    },
                )
                .unwrap()
        );
        assert!(!cleanup_called.get());
        assert!(registry.leases.contains_key("live-lease"));
        assert!(!state_path.exists());
    }

    #[test]
    fn stale_stop_owner_identity_is_rejected_before_cleanup() {
        let owner_pid = std::process::id();
        let owner_start_time = process_start_time(owner_pid).unwrap();
        let active = lease("owned-lease", owner_pid);
        let state_path = unique_test_path("stale-owner-stop.json");
        let cleanup_called = Cell::new(false);
        let mut registry = LeaseRegistry {
            state_path: state_path.clone(),
            leases: HashMap::from([(
                active.lease_id.clone(),
                TunSystemLease {
                    route_guard: None,
                    metadata: active,
                },
            )]),
        };
        let stale_start_time = ProcessStartTime {
            unix_secs: owner_start_time.unix_secs.saturating_add(1),
            micros: owner_start_time.micros,
        };

        let error = registry
            .stop_owned_with_artifact_cleanup(
                "owned-lease",
                None,
                None,
                owner_pid,
                stale_start_time,
                |_, _, _| {
                    cleanup_called.set(true);
                    Ok(())
                },
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("拒绝 StopTun"));
        assert!(!cleanup_called.get());
        assert!(!registry.leases["owned-lease"].metadata.cleanup_requested);
        assert!(!state_path.exists());
    }

    #[test]
    fn matching_stop_owner_identity_can_clean_its_lease() {
        let owner_pid = std::process::id();
        let owner_start_time = process_start_time(owner_pid).unwrap();
        let mut active = lease("owned-lease", owner_pid);
        active.route_state_file = None;
        active.dns_state_file = None;
        let state_path = unique_test_path("matching-owner-stop.json");
        let cleanup_called = Cell::new(false);
        let mut registry = LeaseRegistry {
            state_path: state_path.clone(),
            leases: HashMap::from([(
                active.lease_id.clone(),
                TunSystemLease {
                    route_guard: None,
                    metadata: active,
                },
            )]),
        };

        assert!(
            registry
                .stop_owned_with_artifact_cleanup(
                    "owned-lease",
                    None,
                    None,
                    owner_pid,
                    owner_start_time,
                    |_, _, _| {
                        cleanup_called.set(true);
                        Ok(())
                    },
                )
                .unwrap()
        );
        assert!(cleanup_called.get());
        assert!(registry.leases.is_empty());
        assert!(!state_path.exists());
    }

    #[test]
    fn pf_enable_token_is_persisted_in_lease_registry() {
        let state_path = unique_test_path("pf-token.json");
        let mut metadata = lease("pf-token-lease", std::process::id());
        metadata.route_state_file = None;
        metadata.dns_state_file = None;
        let mut registry = LeaseRegistry {
            state_path: state_path.clone(),
            leases: HashMap::from([(
                metadata.lease_id.clone(),
                TunSystemLease {
                    route_guard: None,
                    metadata,
                },
            )]),
        };

        registry
            .set_pf_enable_token("pf-token-lease", Some("token-123".to_string()))
            .unwrap();
        let persisted = load_persisted_leases(&state_path).unwrap();
        assert_eq!(persisted[0].pf_enable_token.as_deref(), Some("token-123"));

        registry.leases.clear();
        registry.persist().unwrap();
        assert!(!state_path.exists());
    }

    #[test]
    fn pf_token_persist_failure_keeps_token_in_memory_for_immediate_rollback() {
        let parent_file = unique_test_path("pf-token-parent-file");
        fs::write(&parent_file, b"not a directory").unwrap();
        let state_path = parent_file.join("leases.json");
        let mut metadata = lease("pf-token-rollback", std::process::id());
        metadata.route_state_file = None;
        metadata.dns_state_file = None;
        let mut registry = LeaseRegistry {
            state_path,
            leases: HashMap::from([(
                metadata.lease_id.clone(),
                TunSystemLease {
                    route_guard: None,
                    metadata,
                },
            )]),
        };

        assert!(
            registry
                .set_pf_enable_token("pf-token-rollback", Some("token-to-release".to_string()))
                .is_err()
        );
        assert_eq!(
            registry.leases["pf-token-rollback"]
                .metadata
                .pf_enable_token
                .as_deref(),
            Some("token-to-release")
        );

        fs::remove_file(parent_file).unwrap();
    }

    #[test]
    fn helper_info_reports_durable_recovery_protocol_version() {
        let response = TunHelperResponse::HelperInfo {
            protocol_version: TUN_HELPER_PROTOCOL_VERSION,
        };
        let value = serde_json::to_value(response).unwrap();

        assert_eq!(value["type"], "helper_info");
        assert_eq!(value["protocol_version"], 4);
    }

    #[test]
    fn lease_registry_path_is_bound_to_the_socket_name() {
        assert_eq!(
            helper_lease_state_path(Path::new("/var/run/ppaass-ai/tun-helper.sock")),
            PathBuf::from("/var/run/ppaass-ai/tun-helper.sock.leases.json")
        );
    }
}
