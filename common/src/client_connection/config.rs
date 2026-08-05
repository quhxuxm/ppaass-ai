use protocol::{CompressionMode, RsaKeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socket2::Socket;
use std::collections::VecDeque;
use std::sync::{Arc, OnceLock, RwLock};
use std::{fmt::Debug, io, net::SocketAddr, time::Duration};

const PRIVATE_KEY_CACHE_CAPACITY: usize = 8;
type PrivateKeyFingerprint = [u8; 32];
type PrivateKeyCache = VecDeque<(PrivateKeyFingerprint, String, Arc<RsaKeyPair>)>;

fn private_key_cache() -> &'static RwLock<PrivateKeyCache> {
    static CACHE: OnceLock<RwLock<PrivateKeyCache>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(VecDeque::with_capacity(PRIVATE_KEY_CACHE_CAPACITY)))
}

fn cached_private_key(pem: &str) -> Result<Arc<RsaKeyPair>, String> {
    let fingerprint: PrivateKeyFingerprint = Sha256::digest(pem.as_bytes()).into();
    if let Some(key) = private_key_cache()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .find_map(|(cached_fingerprint, cached_pem, key)| {
            (cached_fingerprint == &fingerprint && cached_pem == pem).then(|| key.clone())
        })
    {
        return Ok(key);
    }

    // PEM/ASN.1 parsing is expensive for short-lived TCP targets. Parse outside
    // the lock so unrelated connections are not serialized on a cache miss.
    let parsed =
        Arc::new(RsaKeyPair::from_private_key_pem(pem).map_err(|error| error.to_string())?);
    let mut cache = private_key_cache()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(key) = cache
        .iter()
        .find_map(|(cached_fingerprint, cached_pem, key)| {
            (cached_fingerprint == &fingerprint && cached_pem == pem).then(|| key.clone())
        })
    {
        return Ok(key);
    }
    if cache.len() == PRIVATE_KEY_CACHE_CAPACITY {
        cache.pop_front();
    }
    cache.push_back((fingerprint, pem.to_string(), parsed.clone()));
    Ok(parsed)
}

/// 出站客户端连接的可选接口约束。
///
/// `bind_addr` 负责绑定本地源 IP，`bind_interface` 负责按平台绑定网卡名或 if_index。
/// TUN 模式会同时使用两者，确保 agent->proxy 控制连接不被默认路由重新送回 TUN。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindInterface {
    pub name: Option<String>,
    pub index: Option<u32>,
}

/// 客户端连接配置
pub trait ClientConnectionConfig: Debug {
    /// 获取一个随机选择的远端地址进行连接
    fn remote_addr(&self) -> String;

    /// 认证用户名
    fn username(&self) -> String;

    /// 用于加密的私钥 PEM
    fn private_key_pem(&self) -> Result<String, String>;

    /// Parsed private key shared by short-lived TCP targets and UDP sessions.
    /// The bounded cache avoids repeating PEM/ASN.1 parsing for every flow.
    fn private_key_pair(&self) -> Result<Arc<RsaKeyPair>, String> {
        cached_private_key(&self.private_key_pem()?)
    }

    /// 连接操作的超时时长
    fn timeout_duration(&self) -> Duration;

    /// Framed TCP/TCP-Yamux 消息的压缩模式；原生 UDP 数据报不使用此设置。
    fn compression_mode(&self) -> CompressionMode {
        CompressionMode::None
    }

    /// Optional TCP socket send/receive buffer size for latency-sensitive clients.
    fn tcp_socket_buffer_size(&self) -> Option<usize> {
        None
    }

    /// Optional native UDP transport socket send/receive buffer size.
    ///
    /// Raw UDP has no transport-level retransmission. A larger kernel queue
    /// absorbs short packet bursts without turning scheduler jitter into loss.
    fn udp_socket_buffer_size(&self) -> Option<usize> {
        Some(4 * 1024 * 1024)
    }

    /// 可选的本地套接字绑定地址。
    /// 当返回 `Some` 时，使用 [`tokio::net::TcpSocket`] 在连接前绑定到该地址，
    /// 使 OS 强制通过拥有该 IP 的接口路由连接，绕过任何可能存在的 TUN 默认路由。
    /// 默认返回 `None`（由 OS 自由选择源地址）。
    fn bind_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Optional network interface used together with `bind_addr`.
    ///
    /// TUN mode uses this to keep the agent -> proxy control connection on the
    /// physical interface even after split-default routes point at the TUN.
    fn bind_interface(&self) -> Option<BindInterface> {
        None
    }

    /// Give platform VPN implementations a chance to keep the control socket
    /// outside of the VPN before it connects.
    fn protect_socket(&self, _socket: &Socket, _dst: SocketAddr) -> io::Result<()> {
        Ok(())
    }

    /// Protect a native UDP transport socket from platform VPN routing.
    /// Android overrides this with a fail-closed implementation because a
    /// missing VpnService protector would recursively feed the socket into TUN.
    fn protect_udp_socket(&self, socket: &Socket, dst: SocketAddr) -> io::Result<()> {
        self.protect_socket(socket, dst)
    }
}
