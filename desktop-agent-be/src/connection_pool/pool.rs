//! agent 到 proxy 的连接池。
//!
//! 池里的 legacy 连接是“只完成认证、尚未 Connect 目标”的预热连接；
//! 取出后会发送一次 `ConnectRequest` 并被本次请求消费，不再归还池。
//! 如果启用 Yamux，池维护的是长期外层 session，每次请求在 session 内开子流。

use super::connected_stream::ConnectedStream;
use super::proxy_connection::ProxyConnection;
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use common::{
    BindInterface, TcpTransportMode, YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE,
    YamuxClientConnection, spawn_guarded,
};
use deadpool::unmanaged::Pool;
use protocol::{Address, TransportProtocol};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
use tracing::{debug, info, instrument, warn};

const MAX_CONCURRENT_POOL_CONNECTS: usize = 10;

mod connect;
mod prewarm;
mod yamux;

#[derive(Clone)]
struct YamuxSessionHandle {
    // 本地递增 ID 只用于移除故障 session，不参与协议。
    id: usize,
    connection: YamuxClientConnection,
}

/// 使用 deadpool::unmanaged 的连接池，用于预热代理连接。
/// 连接不会被复用 — 每条连接取出后即消费。
pub struct ConnectionPool {
    /// 预热连接的非托管池
    pool: Pool<ProxyConnection>,
    config: Arc<AgentConfig>,
    pool_name: &'static str,
    pool_size: usize,
    /// 请求补充连接的通知机制
    refill_notify: Arc<Notify>,
    /// 追踪池中可用连接数
    available: Arc<AtomicUsize>,
    /// 连接在池中停留的最长时间
    max_connection_age: Duration,
    /// TUN 模式激活时保存物理网卡的 IP 地址。
    /// 每个新建的代理 TCP 连接都会绑定到该 IP，确保流量从物理接口出，
    /// 而不会回环进入 TUN 设备。
    proxy_bind_ip: Arc<std::sync::RwLock<Option<IpAddr>>>,
    /// TUN 模式激活时保存物理出口接口。
    proxy_bind_interface: Arc<std::sync::RwLock<Option<BindInterface>>>,
    use_yamux: bool,
    // auto/yamux/legacy 配置影响是否优先尝试 Yamux，以及失败时能否回退 legacy。
    yamux_mode: Option<TcpTransportMode>,
    yamux_transport: Option<TransportProtocol>,
    // 外层虚拟地址：TCP 池连 TcpYamux，UDP 池连 UdpYamux。
    yamux_outer_address: Option<Address>,
    // 长期复用的 Yamux 外层 session 集合。
    yamux_sessions: Arc<Mutex<Vec<YamuxSessionHandle>>>,
    yamux_refill_lock: Arc<Mutex<()>>,
    yamux_next_index: AtomicUsize,
    yamux_next_session_id: AtomicUsize,
}

impl ConnectionPool {
    pub fn new(config: Arc<AgentConfig>) -> Self {
        let pool_size = config.tcp_pool_size;
        Self::new_with_size(config, pool_size, "tcp_pool")
    }

    pub fn new_with_size(
        config: Arc<AgentConfig>,
        pool_size: usize,
        pool_name: &'static str,
    ) -> Self {
        // unmanaged pool 容量略大于目标值，给并发补充和消费留出余量。
        let pool = Pool::new(pool_capacity(pool_size));
        let refill_notify = Arc::new(Notify::new());
        let available = Arc::new(AtomicUsize::new(0));
        let max_connection_age = Duration::from_secs(config.pool_max_connection_age_secs);
        let (yamux_mode, yamux_transport, yamux_outer_address) = match pool_name {
            "tcp_pool" => (
                Some(config.transport.tcp_mode),
                Some(TransportProtocol::Tcp),
                Some(Address::TcpYamux),
            ),
            "udp_pool" => (
                Some(config.transport.udp_mode),
                Some(TransportProtocol::Udp),
                Some(Address::UdpYamux),
            ),
            _ => (None, None, None),
        };
        let use_yamux = yamux_mode
            .map(|mode| mode != TcpTransportMode::Legacy)
            .unwrap_or(false);
        Self {
            pool,
            config,
            pool_name,
            pool_size,
            refill_notify,
            available,
            max_connection_age,
            proxy_bind_ip: Arc::new(std::sync::RwLock::new(None)),
            proxy_bind_interface: Arc::new(std::sync::RwLock::new(None)),
            use_yamux,
            yamux_mode,
            yamux_transport,
            yamux_outer_address,
            yamux_sessions: Arc::new(Mutex::new(Vec::new())),
            yamux_refill_lock: Arc::new(Mutex::new(())),
            yamux_next_index: AtomicUsize::new(0),
            yamux_next_session_id: AtomicUsize::new(0),
        }
    }

    // ── 绑定 IP 管理（TUN 模式）──────────────────────────────────────────────

    /// 设置代理连接应当绑定的物理网卡 IP。
    /// 应在安装 TUN 路由规则之前调用，确保后续所有代理连接
    /// （包括补充任务创建的连接）都绕过 TUN。
    pub fn set_proxy_bind_ip(&self, ip: Option<IpAddr>) {
        // TUN 模式启动/退出时会切换此值，后台补充任务创建新连接时读取它。
        if let Ok(mut guard) = self.proxy_bind_ip.write() {
            *guard = ip;
        }
    }

    /// 设置代理连接应当绑定的物理出口接口。
    pub fn set_proxy_bind_interface(&self, interface: Option<BindInterface>) {
        if let Ok(mut guard) = self.proxy_bind_interface.write() {
            *guard = interface;
        }
    }

    fn get_proxy_bind_ip(&self) -> Option<IpAddr> {
        // 读取失败时保守退回不绑定，让连接错误暴露给上层日志。
        self.proxy_bind_ip.read().ok().and_then(|g| *g)
    }

    fn get_proxy_bind_interface(&self) -> Option<BindInterface> {
        self.proxy_bind_interface
            .read()
            .ok()
            .and_then(|g| g.clone())
    }
}

fn pool_capacity(pool_size: usize) -> usize {
    ((pool_size as f32 * 1.5) as usize).max(1)
}

fn should_retry_pooled_connect_error(err: &crate::error::AgentError) -> bool {
    match err {
        // 代理明确返回 ConnectResponse 失败时，多半是目标不可达、带宽限制或上游错误，
        // 重试同一个目标不会修复这类业务失败。
        crate::error::AgentError::Connection(message) => !message.starts_with("连接失败:"),
        crate::error::AgentError::Io(_) | crate::error::AgentError::Protocol(_) => true,
        _ => false,
    }
}

fn should_fallback_yamux_error(err: &crate::error::AgentError) -> bool {
    match err {
        crate::error::AgentError::Connection(message) => !is_yamux_target_connect_error(message),
        crate::error::AgentError::Io(_) | crate::error::AgentError::Protocol(_) => true,
        _ => false,
    }
}

fn is_yamux_target_connect_error(message: &str) -> bool {
    message.starts_with("连接失败:") || message == YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
}
