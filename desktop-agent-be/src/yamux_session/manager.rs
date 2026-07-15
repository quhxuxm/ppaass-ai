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
    BindInterface, UdpClientConnection, YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE,
    YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE, YamuxClientConnection,
};
use protocol::{Address, TransportProtocol};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tracing::{debug, instrument, warn};

const MAX_CONCURRENT_SESSION_CONNECTS: usize = 20;

mod connect;
mod yamux;

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
}

impl YamuxSessionManager {
    pub fn new(config: Arc<AgentConfig>) -> Self {
        Self::new_for_transport(config, TransportProtocol::Tcp, "tcp_direct_connections")
    }

    pub fn new_udp(config: Arc<AgentConfig>) -> Self {
        Self::new_for_transport(config, TransportProtocol::Udp, "udp_yamux_sessions")
    }

    fn new_for_transport(
        config: Arc<AgentConfig>,
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
        }
    }

    pub fn set_proxy_bind_ip(&self, ip: Option<IpAddr>) {
        if let Ok(mut guard) = self.proxy_bind_ip.write() {
            *guard = ip;
        }
    }

    pub fn set_proxy_bind_interface(&self, interface: Option<BindInterface>) {
        if let Ok(mut guard) = self.proxy_bind_interface.write() {
            *guard = interface;
        }
    }

    fn get_proxy_bind_ip(&self) -> Option<IpAddr> {
        let guard = self.proxy_bind_ip.read().ok()?;
        *guard
    }

    fn get_proxy_bind_interface(&self) -> Option<BindInterface> {
        let guard = self.proxy_bind_interface.read().ok()?;
        guard.clone()
    }

    fn next_udp_session_slot(&self) -> usize {
        // 只有 UDP manager 会进入此路径，AgentConfig 已把 pool size 夹到至少 1。
        debug_assert_eq!(self.yamux_transport, TransportProtocol::Udp);
        debug_assert!(!self.udp_sessions.is_empty());
        self.udp_next_index.fetch_add(1, Ordering::AcqRel) % self.udp_sessions.len()
    }
}

fn is_yamux_target_connect_error(message: &str) -> bool {
    message.starts_with("连接失败:")
        || message == YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
        || message == "连接目标响应超时"
}

fn is_yamux_session_capacity_error(message: &str) -> bool {
    message == YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_AGENT_CONFIG: &str = r#"
listen_addr = "127.0.0.1:10080"
proxy_addrs = ["127.0.0.1:8080"]
username = "user1"
private_key_path = "keys/user1.pem"
"#;

    #[test]
    fn yamux_capacity_errors_are_not_target_connect_errors() {
        assert!(!is_yamux_target_connect_error(
            YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE
        ));
        assert!(is_yamux_session_capacity_error(
            YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE
        ));
    }

    #[test]
    fn yamux_response_timeouts_do_not_close_session() {
        assert!(is_yamux_target_connect_error(
            YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
        ));
        assert!(is_yamux_target_connect_error("连接目标响应超时"));
    }

    #[test]
    fn only_udp_manager_allocates_native_udp_pool() {
        let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();
        let config = Arc::new(config);
        let tcp_manager = YamuxSessionManager::new(config.clone());
        let udp_manager = YamuxSessionManager::new_udp(config);

        assert!(tcp_manager.udp_sessions.is_empty());
        assert_eq!(udp_manager.udp_sessions.len(), 4);
        let slots: Vec<_> = (0..10)
            .map(|_| udp_manager.next_udp_session_slot())
            .collect();
        assert_eq!(slots, vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1]);
    }

    #[test]
    fn tcp_transport_mode_does_not_allocate_native_udp_pool() {
        let config: AgentConfig =
            toml::from_str(&(MINIMAL_AGENT_CONFIG.to_owned() + "transport_mode = \"tcp\"\n"))
                .unwrap();
        let manager = YamuxSessionManager::new_udp(Arc::new(config));

        assert!(manager.udp_sessions.is_empty());
    }
}
