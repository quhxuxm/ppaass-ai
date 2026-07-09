/// 到上游代理的连接。
/// 作为客户端连接到下一跳：TCP 使用 direct framed TCP，UDP 继续使用 Yamux。
use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use common::{
    AuthenticatedConnection, ClientConnectionConfig, ClientStream, YamuxClientConnection,
    YamuxClientStream,
};
use protocol::{Address, TransportProtocol};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{fmt::Debug, fs::read_to_string, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

/// ClientConnection 特征的配置适配器
#[derive(Debug)]
struct ProxyClientConfig<'a> {
    config: &'a ProxyConfig,
}

impl<'a> ProxyClientConfig<'a> {
    fn new(config: &'a ProxyConfig) -> Result<Self> {
        // 转发模式依赖三项配置；提前校验能把错误定位在连接上游之前。
        let addrs = config.upstream_proxy_addrs.as_ref().ok_or_else(|| {
            ProxyError::Configuration(
                "Upstream proxy addresses not configured or empty".to_string(),
            )
        })?;
        if addrs.is_empty() {
            return Err(ProxyError::Configuration(
                "Upstream proxy addresses not configured or empty".to_string(),
            ));
        }
        config.upstream_username.as_ref().ok_or_else(|| {
            ProxyError::Configuration("Upstream username not configured".to_string())
        })?;
        config.upstream_private_key_path.as_ref().ok_or_else(|| {
            ProxyError::Configuration("Upstream private key path not configured".to_string())
        })?;

        Ok(Self { config })
    }
}

impl<'a> ClientConnectionConfig for ProxyClientConfig<'a> {
    fn remote_addr(&self) -> String {
        // 每次上游连接随机选择一个地址，提供简单的负载分散和故障绕行。
        use rand::prelude::*;
        let mut rng = rand::rng();
        self.config
            .upstream_proxy_addrs
            .as_ref()
            .expect("validated in ProxyClientConfig::new")
            .choose(&mut rng)
            .cloned()
            .expect("validated non-empty in ProxyClientConfig::new")
    }

    fn username(&self) -> String {
        // new() 已验证配置存在，这里按 ClientConnectionConfig trait 返回 owned 值。
        self.config
            .upstream_username
            .as_ref()
            .cloned()
            .expect("validated in ProxyClientConfig::new")
    }

    fn private_key_pem(&self) -> std::result::Result<String, String> {
        // 私钥仍从文件读取，避免把敏感内容常驻在 ProxyConfig 里。
        let path = self
            .config
            .upstream_private_key_path
            .as_ref()
            .ok_or_else(|| "Private key path not configured".to_string())?;

        read_to_string(path).map_err(|e| e.to_string())
    }

    fn timeout_duration(&self) -> Duration {
        // 上游连接复用 proxy 的连接超时配置。
        Duration::from_secs(self.config.connect_timeout_secs)
    }
}

/// 到上游代理的连接
pub struct UpstreamConnection {
    kind: UpstreamConnectionKind,
}

enum UpstreamConnectionKind {
    Direct(ClientStream<TcpStream>),
    Yamux {
        connection: YamuxClientConnection,
        stream: YamuxClientStream,
    },
}

impl UpstreamConnection {
    /// 建立到上游代理的连接
    pub async fn connect(
        config: &ProxyConfig,
        target_address: Address,
        transport: TransportProtocol,
    ) -> Result<Self> {
        // proxy 在转发模式下也作为客户端连接下一跳 proxy。
        let config_adapter = ProxyClientConfig::new(config)?;

        debug!("正在连接上游代理");

        if transport == TransportProtocol::Tcp {
            let connection = AuthenticatedConnection::connect(&config_adapter)
                .await
                .map_err(|e| ProxyError::Connection(e.to_string()))?;
            let (stream, _request_id) = connection
                .connect_to_target(target_address, transport)
                .await
                .map_err(|e| ProxyError::Connection(e.to_string()))?;

            return Ok(Self {
                kind: UpstreamConnectionKind::Direct(stream),
            });
        }

        let yamux_connection =
            YamuxClientConnection::connect_for(&config_adapter, transport, config.yamux.settings())
                .await
                .map_err(|e| ProxyError::Connection(e.to_string()))?;
        let (stream, _request_id) = yamux_connection
            .connect_to_target(target_address, transport)
            .await
            .map_err(|e| ProxyError::Connection(e.to_string()))?;

        Ok(Self {
            kind: UpstreamConnectionKind::Yamux {
                connection: yamux_connection,
                stream,
            },
        })
    }

    pub async fn close(self) {
        if let UpstreamConnectionKind::Yamux { connection, .. } = self.kind {
            connection.close().await;
        }
    }
}

impl AsyncRead for UpstreamConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.kind {
            UpstreamConnectionKind::Direct(stream) => Pin::new(stream).poll_read(cx, buf),
            UpstreamConnectionKind::Yamux { stream, .. } => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.kind {
            UpstreamConnectionKind::Direct(stream) => Pin::new(stream).poll_write(cx, buf),
            UpstreamConnectionKind::Yamux { stream, .. } => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.kind {
            UpstreamConnectionKind::Direct(stream) => Pin::new(stream).poll_flush(cx),
            UpstreamConnectionKind::Yamux { stream, .. } => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.kind {
            UpstreamConnectionKind::Direct(stream) => Pin::new(stream).poll_shutdown(cx),
            UpstreamConnectionKind::Yamux { stream, .. } => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl Unpin for UpstreamConnection {}
