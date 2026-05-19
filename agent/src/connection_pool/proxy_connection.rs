use std::{
    fs::read_to_string,
    net::{IpAddr, SocketAddr},
    time::Duration,
    time::Instant,
};

use super::connected_stream::ConnectedStream;
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use common::{AuthenticatedConnection, BindInterface, ClientConnectionConfig};
use protocol::Address;
use tracing::{debug, info, instrument};

/// ClientConnection 特征的配置适配器
#[derive(Debug)]
struct AgentClientConfig<'a> {
    config: &'a AgentConfig,
    /// 当为 `Some` 时，TCP 套接字在连接前会绑定到此地址，
    /// 强制连接通过物理接口出，绕过可能存在的 TUN 默认路由。
    bind_ip: Option<IpAddr>,
    bind_interface: Option<BindInterface>,
}

impl<'a> AgentClientConfig<'a> {
    fn new(
        config: &'a AgentConfig,
        bind_ip: Option<IpAddr>,
        bind_interface: Option<BindInterface>,
    ) -> Self {
        Self {
            config,
            bind_ip,
            bind_interface,
        }
    }
}

impl<'a> ClientConnectionConfig for AgentClientConfig<'a> {
    fn remote_addr(&self) -> String {
        // 每条代理连接随机选择一个 proxy 地址，实现简单负载分散。
        use rand::prelude::*;
        let mut rng = rand::rng();
        self.config
            .proxy_addrs
            .choose(&mut rng)
            .cloned()
            .unwrap_or_default()
    }

    fn username(&self) -> String {
        // common::AuthenticatedConnection 需要 owned 用户名。
        self.config.username.clone()
    }

    fn private_key_pem(&self) -> std::result::Result<String, String> {
        // 私钥按连接读取，避免敏感内容被 AgentConfig 长期持有。
        read_to_string(&self.config.private_key_path).map_err(|e| e.to_string())
    }

    fn timeout_duration(&self) -> Duration {
        // 认证 TCP 连接和握手共用配置的连接超时。
        Duration::from_secs(self.config.connect_timeout_secs)
    }

    fn bind_addr(&self) -> Option<SocketAddr> {
        // 端口 0 ⇒ OS 自动选择临时端口
        self.bind_ip.map(|ip| SocketAddr::new(ip, 0))
    }

    fn bind_interface(&self) -> Option<BindInterface> {
        self.bind_interface.clone()
    }
}

/// 到代理的一次性认证连接。
/// 此连接用于一次请求后即丢弃。
pub struct ProxyConnection {
    auth_conn: AuthenticatedConnection,
    /// 连接创建时间，用于强制池中连接最大存活时间，
    /// 避免使用代理端已因空闲超时关闭的连接。
    created_at: Instant,
}

impl ProxyConnection {
    /// 创建到代理的新认证连接。
    ///
    /// `bind_ip` — 当为 `Some` 时，出站 TCP 套接字会绑定到该 IP 地址。
    /// TUN 模式下调用方在此传入物理网卡 IP，使连接绕过 TUN 路由。
    #[instrument(skip(config))]
    pub async fn new(
        config: &AgentConfig,
        bind_ip: Option<IpAddr>,
        bind_interface: Option<BindInterface>,
    ) -> Result<Self> {
        let addr_display = if config.proxy_addrs.len() == 1 {
            config.proxy_addrs[0].clone()
        } else {
            format!("[{}]", config.proxy_addrs.join(", "))
        };
        debug!(
            "正在创建代理连接：{} (bind_ip={:?}, bind_interface={:?})",
            addr_display, bind_ip, bind_interface
        );
        let config_adapter = AgentClientConfig::new(config, bind_ip, bind_interface);

        // 这里只完成到 proxy 的认证，不立即发送目标连接请求。
        let auth_conn = AuthenticatedConnection::authenticate_only(&config_adapter)
            .await
            .map_err(|e| AgentError::Connection(e.to_string()))?;

        info!("认证成功");

        Ok(Self {
            auth_conn,
            created_at: Instant::now(),
        })
    }

    /// 如果连接在池中停留时间超过 `max_age`，返回 true。
    /// 过期连接应被丢弃而非使用。
    pub fn is_expired(&self, max_age: Duration) -> bool {
        self.created_at.elapsed() >= max_age
    }

    /// 连接到目标地址并返回双向流句柄
    #[instrument(skip(self))]
    pub async fn connect_target(
        self,
        address: Address,
        transport: protocol::TransportProtocol,
    ) -> Result<ConnectedStream> {
        debug!("正在连接目标：{:?}", address);

        // 预热连接被消费后发送一次目标 connect 请求，并取得对应 stream_id。
        let (stream, request_id) = self
            .auth_conn
            .connect_to_target(address.clone(), transport)
            .await
            .map_err(|e| AgentError::Connection(e.to_string()))?;

        info!("已连接到目标：{:?}", address);

        Ok(ConnectedStream::new(
            stream.writer,
            stream.reader,
            request_id,
        ))
    }
}
