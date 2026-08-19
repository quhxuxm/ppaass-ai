//! agent 到 proxy 的目标连接管理器。
//!
//! TCP 语义始终使用独立 framed TCP 连接。UDP 模式只影响 UDP 语义：在
//! 原生加密 UDP 会话池上打开逻辑 channel；TCP 模式下，UDP 语义使用 raw
//! TCP 上的 Yamux 连接池。

use super::proxy_connection::new_yamux_connection;
use super::target_stream::YamuxTargetStream;
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use common::{
    BindInterface, ProxyEndpointAffinity, UdpClientConnection,
    YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE, YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE,
    YamuxClientConnection,
};
use protocol::{Address, TransportProtocol};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tracing::{debug, instrument, warn};

const MAX_CONCURRENT_SESSION_CONNECTS: usize = 20;

pub mod connect;
mod yamux;

pub use connect::{ProxyStreamRoute, is_native_udp_timeout, proxy_stream_route};

#[derive(Clone)]
struct YamuxSessionHandle {
    id: usize,
    connection: YamuxClientConnection,
}

#[derive(Clone)]
struct UdpSessionHandle {
    id: usize,
    connection: UdpClientConnection,
}

pub struct YamuxSessionManager {
    config: Arc<AgentConfig>,
    proxy_addrs: Arc<Vec<String>>,
    // TUN 模式安装默认路由前解析并固定 proxy IP，避免系统 DNS 被接管后，
    // proxy 重连反过来依赖尚未建立的 DNS proxy 通道。
    proxy_addrs_override: Arc<std::sync::RwLock<Option<Arc<Vec<String>>>>>,
    proxy_affinity: Arc<ProxyEndpointAffinity>,
    manager_name: &'static str,
    yamux_transport: TransportProtocol,
    proxy_bind_ip: Arc<std::sync::RwLock<Option<IpAddr>>>,
    proxy_bind_interface: Arc<std::sync::RwLock<Option<BindInterface>>>,
    yamux_sessions: Arc<Mutex<Vec<YamuxSessionHandle>>>,
    // 每个 slot 拥有独立原生 UDP socket/会话密钥/序号空间。slot 级锁使首次
    // 并发建连可以平行进行，不会被一把全局锁串行化。
    udp_sessions: Vec<Mutex<Option<UdpSessionHandle>>>,
    yamux_refill_lock: Arc<Mutex<()>>,
    udp_next_index: AtomicUsize,
    udp_next_session_id: AtomicUsize,
    yamux_next_index: AtomicUsize,
    yamux_next_session_id: AtomicUsize,
    // 自动模式按原生 UDP pool slot 独立记录回退状态。一个 session 超时不会
    // 让其他仍可用的 UDP session 一并切到 TCP。
    auto_udp_fallback_to_yamux: Vec<AtomicBool>,
}

impl YamuxSessionManager {
    pub fn new(config: Arc<AgentConfig>, proxy_addrs: Arc<Vec<String>>) -> Self {
        Self::new_with_affinity(
            config,
            proxy_addrs,
            Arc::new(ProxyEndpointAffinity::default()),
        )
    }

    pub fn new_udp(config: Arc<AgentConfig>, proxy_addrs: Arc<Vec<String>>) -> Self {
        Self::new_udp_with_affinity(
            config,
            proxy_addrs,
            Arc::new(ProxyEndpointAffinity::default()),
        )
    }

    pub fn new_with_affinity(
        config: Arc<AgentConfig>,
        proxy_addrs: Arc<Vec<String>>,
        proxy_affinity: Arc<ProxyEndpointAffinity>,
    ) -> Self {
        Self::new_for_transport(
            config,
            proxy_addrs,
            proxy_affinity,
            TransportProtocol::Tcp,
            "tcp_direct_connections",
        )
    }

    pub fn new_udp_with_affinity(
        config: Arc<AgentConfig>,
        proxy_addrs: Arc<Vec<String>>,
        proxy_affinity: Arc<ProxyEndpointAffinity>,
    ) -> Self {
        Self::new_for_transport(
            config,
            proxy_addrs,
            proxy_affinity,
            TransportProtocol::Udp,
            "udp_yamux_sessions",
        )
    }

    fn new_for_transport(
        config: Arc<AgentConfig>,
        proxy_addrs: Arc<Vec<String>>,
        proxy_affinity: Arc<ProxyEndpointAffinity>,
        yamux_transport: TransportProtocol,
        manager_name: &'static str,
    ) -> Self {
        // TCP manager 始终走 direct framed TCP，不需要占用 UDP socket/内存。
        // 只有 UDP manager 保留可配置的原生 UDP 会话池。
        let udp_pool_size = if config.transport_mode.uses_native_udp_for(yamux_transport) {
            config.effective_udp_session_pool_size()
        } else {
            0
        };
        Self {
            config,
            proxy_addrs,
            proxy_addrs_override: Arc::new(std::sync::RwLock::new(None)),
            proxy_affinity,
            manager_name,
            yamux_transport,
            proxy_bind_ip: Arc::new(std::sync::RwLock::new(None)),
            proxy_bind_interface: Arc::new(std::sync::RwLock::new(None)),
            yamux_sessions: Arc::new(Mutex::new(Vec::new())),
            udp_sessions: (0..udp_pool_size).map(|_| Mutex::new(None)).collect(),
            yamux_refill_lock: Arc::new(Mutex::new(())),
            udp_next_index: AtomicUsize::new(0),
            udp_next_session_id: AtomicUsize::new(0),
            yamux_next_index: AtomicUsize::new(0),
            yamux_next_session_id: AtomicUsize::new(0),
            auto_udp_fallback_to_yamux: (0..udp_pool_size)
                .map(|_| AtomicBool::new(false))
                .collect(),
        }
    }

    pub fn set_proxy_bind_ip(&self, ip: Option<IpAddr>) {
        if let Ok(mut guard) = self.proxy_bind_ip.write() {
            *guard = ip;
        }
    }

    pub fn set_proxy_addrs_override(&self, addrs: Option<Arc<Vec<String>>>) {
        if let Ok(mut guard) = self.proxy_addrs_override.write() {
            *guard = addrs;
        }
    }

    pub fn proxy_addrs(&self) -> Arc<Vec<String>> {
        self.proxy_addrs_override
            .read()
            .ok()
            .and_then(|guard| guard.clone())
            .unwrap_or_else(|| self.proxy_addrs.clone())
    }

    pub fn set_proxy_bind_interface(&self, interface: Option<BindInterface>) {
        if let Ok(mut guard) = self.proxy_bind_interface.write() {
            *guard = interface;
        }
    }

    pub fn proxy_bind_ip(&self) -> Option<IpAddr> {
        let guard = self.proxy_bind_ip.read().ok()?;
        *guard
    }

    pub fn proxy_bind_interface(&self) -> Option<BindInterface> {
        let guard = self.proxy_bind_interface.read().ok()?;
        guard.clone()
    }

    pub fn next_udp_session_slot(&self) -> usize {
        // 只有 UDP manager 会进入此路径，AgentConfig 已把 pool size 夹到至少 1。
        debug_assert_eq!(self.yamux_transport, TransportProtocol::Udp);
        debug_assert!(!self.udp_sessions.is_empty());
        self.udp_next_index.fetch_add(1, Ordering::AcqRel) % self.udp_sessions.len()
    }

    pub fn native_udp_session_pool_size(&self) -> usize {
        self.udp_sessions.len()
    }

    pub fn auto_udp_fallback_slot_count(&self) -> usize {
        self.auto_udp_fallback_to_yamux.len()
    }

    pub fn set_auto_udp_fallback(&self, slot: usize, enabled: bool) {
        self.auto_udp_fallback_to_yamux[slot].store(enabled, Ordering::Release);
    }

    pub fn auto_udp_fallback(&self, slot: usize) -> bool {
        self.auto_udp_fallback_to_yamux[slot].load(Ordering::Acquire)
    }
}

pub fn is_yamux_target_connect_error(message: &str) -> bool {
    message.starts_with("连接失败:")
        || message == YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
        || message == "连接目标响应超时"
}

pub fn is_yamux_session_capacity_error(message: &str) -> bool {
    message == YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE
}
