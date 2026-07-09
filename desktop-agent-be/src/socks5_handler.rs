//! 本地 SOCKS5 代理入口。
//!
//! TCP CONNECT/BIND 走 `tcp.rs`，UDP ASSOCIATE 走 `udp_associate.rs`。
//! 本模块只负责 SOCKS5 握手、命令分发，以及把 fast-socks5 的目标地址
//! 转成项目内部的 `protocol::Address`。

use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::{AgentError, Result};
use crate::telemetry;
use crate::yamux_session::{YamuxSessionManager, YamuxTargetStream};
use dashmap::DashMap;
use fast_socks5::server::{
    NoAuthentication, Socks5ServerProtocol, SocksServerError,
    states::{CommandRead, Opened},
};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use protocol::{Address, TransportProtocol, UdpRelayPacket};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::{Sender, channel};
use tracing::{debug, error, info, instrument, trace, warn};

mod tcp;
#[cfg(test)]
mod tests;
mod udp_associate;
mod udp_relay;

use tcp::{handle_tcp_bind, handle_tcp_connect};
use udp_associate::handle_udp_associate;

#[instrument(skip(stream, tcp_sessions, udp_sessions, direct_checker))]
pub async fn handle_socks5_connection(
    stream: TcpStream,
    tcp_sessions: Arc<YamuxSessionManager>,
    udp_sessions: Arc<YamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    info!("处理 SOCKS5 连接");
    // UDP ASSOCIATE 回复地址尽量沿用 TCP 控制连接的本地地址族。
    let control_local_ip = stream.local_addr().ok().map(|addr| addr.ip());

    // 使用新的 fast-socks5 1.0 API 和 Socks5ServerProtocol
    let protocol: Socks5ServerProtocol<TcpStream, Opened> = Socks5ServerProtocol::start(stream);

    // 协商认证 - 本地代理默认无认证；用户身份由 agent->proxy 连接的密钥认证承担。
    let auth_state = protocol
        .negotiate_auth::<NoAuthentication>(&[NoAuthentication])
        .await
        .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

    // 完成认证并获取已认证状态
    let authenticated = Socks5ServerProtocol::finish_auth(auth_state);

    // 读取 SOCKS5 命令（CONNECT、BIND 等）
    let (protocol, command, target_addr) = authenticated
        .read_command()
        .await
        .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

    info!("SOCKS5 命令: {:?}, 目标: {:?}", command, target_addr);

    match command {
        // CONNECT 是最常见路径：客户端要求 agent 主动连接目标。
        Socks5Command::TCPConnect => {
            handle_tcp_connect(protocol, target_addr, tcp_sessions, direct_checker).await
        }
        // BIND 让 agent 监听一个端口等待远端主动连入。
        Socks5Command::TCPBind => {
            handle_tcp_bind(protocol, target_addr, tcp_sessions, direct_checker).await
        }
        // UDP ASSOCIATE 通过 TCP 控制连接维持 UDP 会话生命周期。
        Socks5Command::UDPAssociate => {
            handle_udp_associate(
                protocol,
                target_addr,
                udp_sessions,
                control_local_ip,
                direct_checker,
            )
            .await
        }
    }
}

fn convert_target_addr(target: &TargetAddr) -> Address {
    // fast-socks5 的目标地址转换为项目内部协议地址。
    match target {
        TargetAddr::Ip(addr) => match addr {
            std::net::SocketAddr::V4(v4) => Address::Ipv4 {
                addr: v4.ip().octets(),
                port: v4.port(),
            },
            std::net::SocketAddr::V6(v6) => Address::Ipv6 {
                addr: v6.ip().octets(),
                port: v6.port(),
            },
        },
        TargetAddr::Domain(host, port) => Address::Domain {
            host: host.clone(),
            port: *port,
        },
    }
}

fn format_target_addr(target: &TargetAddr) -> String {
    // 用于日志和流量统计的人类可读目标地址。
    match target {
        TargetAddr::Ip(addr) => addr.to_string(),
        TargetAddr::Domain(host, port) => format!("{host}:{port}"),
    }
}
