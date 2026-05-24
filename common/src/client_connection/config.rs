use socket2::Socket;
use std::{fmt::Debug, io, net::SocketAddr, time::Duration};

/// Optional interface constraint for outbound client connections.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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

    /// 连接操作的超时时长
    fn timeout_duration(&self) -> Duration;

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
}
