//! agent 到 proxy 的 raw Yamux session 池。
//!
//! TCP 和 UDP 语义分别使用独立 `ConnectionPool` 实例。池中每个 session 都是一条
//! raw TCP 上的 Yamux 外层连接；每个目标连接会打开一个子 stream，并在子 stream
//! 内执行完整的 PPAASS Auth/Connect/Data 加密协议。

use super::connected_stream::ConnectedStream;
use super::proxy_connection::new_yamux_connection;
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use common::{BindInterface, YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE, YamuxClientConnection};
use protocol::{Address, TransportProtocol};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn};

const MAX_CONCURRENT_POOL_CONNECTS: usize = 20;

mod connect;
mod prewarm;
mod yamux;

#[derive(Clone)]
struct YamuxSessionHandle {
    id: usize,
    connection: YamuxClientConnection,
}

pub struct ConnectionPool {
    config: Arc<AgentConfig>,
    pool_name: &'static str,
    yamux_transport: TransportProtocol,
    prewarm_started: AtomicBool,
    proxy_bind_ip: Arc<std::sync::RwLock<Option<IpAddr>>>,
    proxy_bind_interface: Arc<std::sync::RwLock<Option<BindInterface>>>,
    yamux_sessions: Arc<Mutex<Vec<YamuxSessionHandle>>>,
    yamux_refill_lock: Arc<Mutex<()>>,
    yamux_next_index: AtomicUsize,
    yamux_next_session_id: AtomicUsize,
}

impl ConnectionPool {
    pub fn new(config: Arc<AgentConfig>) -> Self {
        Self::new_for_transport(config, TransportProtocol::Tcp, "tcp_pool")
    }

    pub fn new_udp(config: Arc<AgentConfig>) -> Self {
        Self::new_for_transport(config, TransportProtocol::Udp, "udp_pool")
    }

    fn new_for_transport(
        config: Arc<AgentConfig>,
        yamux_transport: TransportProtocol,
        pool_name: &'static str,
    ) -> Self {
        Self {
            config,
            pool_name,
            yamux_transport,
            prewarm_started: AtomicBool::new(false),
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
    message.starts_with("连接失败:") || message == YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
}
