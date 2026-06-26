//! agent 到 proxy 的 proxy 目标连接管理器。
//!
//! TCP 语义使用独立 framed TCP 连接；UDP 语义继续使用 raw TCP 上的 Yamux 外层
//! 连接池，并在子 stream 内执行完整的 PPAASS Auth/Connect/Data 加密协议。

use super::proxy_connection::new_yamux_connection;
use super::target_stream::YamuxTargetStream;
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use common::{
    BindInterface, YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE,
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

pub struct YamuxSessionManager {
    config: Arc<AgentConfig>,
    manager_name: &'static str,
    yamux_transport: TransportProtocol,
    proxy_bind_ip: Arc<std::sync::RwLock<Option<IpAddr>>>,
    proxy_bind_interface: Arc<std::sync::RwLock<Option<BindInterface>>>,
    yamux_sessions: Arc<Mutex<Vec<YamuxSessionHandle>>>,
    yamux_refill_lock: Arc<Mutex<()>>,
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
        Self {
            config,
            manager_name,
            yamux_transport,
            proxy_bind_ip: Arc::new(std::sync::RwLock::new(None)),
            proxy_bind_interface: Arc::new(std::sync::RwLock::new(None)),
            yamux_sessions: Arc::new(Mutex::new(Vec::new())),
            yamux_refill_lock: Arc::new(Mutex::new(())),
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
}
