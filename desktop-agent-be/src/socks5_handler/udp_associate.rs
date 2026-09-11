//! SOCKS5 UDP ASSOCIATE 控制与本地 UDP 入口。
//!
//! TCP 控制连接只负责告诉客户端“请把 UDP 包发到哪个本地地址”，并维持会话生命周期。
//! 真正的 UDP 数据包在本模块解析 SOCKS5 UDP 头后，按直连规则选择本地直连或共享 UDP relay。

use super::udp_relay::SocksUdpRelay;
use super::*;

mod direct;

use direct::{DirectUdpFlowKey, spawn_direct_udp_flow};

pub(super) async fn handle_udp_associate(
    protocol: Socks5ServerProtocol<CapturedTcpStream, CommandRead>,
    _target_addr: TargetAddr,
    udp_sessions: Arc<YamuxSessionManager>,
    control_local_ip: Option<IpAddr>,
    direct_checker: Arc<DirectAccessChecker>,
    packet_capture: PacketCaptureController,
) -> Result<()> {
    info!("处理 UDP ASSOCIATE");

    // 在随机端口上绑定 UDP 套接字，客户端后续会把 SOCKS5 UDP datagram 发到这里。
    let udp_bind_addr = udp_associate_bind_addr(control_local_ip);
    let udp_socket = UdpSocket::bind(udp_bind_addr)
        .await
        .map_err(|e| AgentError::Socks5(format!("绑定 UDP 套接字失败: {}", e)))?;

    let bind_addr = udp_socket
        .local_addr()
        .map_err(|e| AgentError::Socks5(format!("获取本地地址失败: {}", e)))?;
    let reply_addr = resolve_udp_associate_reply_addr(bind_addr, control_local_ip);

    info!("UDP 关联绑定到 {}, 回复地址 {}", bind_addr, reply_addr);

    // 回复成功，包含绑定地址
    let mut tcp_stream = protocol
        .reply_success(reply_addr)
        .await
        .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

    let udp_socket = Arc::new(udp_socket);
    let udp_sessions = udp_sessions.clone();

    // 客户端向 `bind_addr` 发送 UDP 数据包

    // 需要保持 TCP 流存活以维持关联；客户端关闭 TCP 控制连接后，UDP 会话也结束。
    let keep_alive = async move {
        let mut buf = [0u8; 1];
        // 如果 read 返回 0（EOF）或错误，表示客户端已关闭连接
        let _ = tcp_stream.read(&mut buf).await;
        debug!("UDP 关联 TCP 控制通道已关闭");
    };

    let udp_handler = process_udp_traffic(
        udp_socket,
        udp_sessions,
        direct_checker,
        reply_addr,
        packet_capture,
    );

    tokio::select! {
        _ = keep_alive => {
           // 客户端关闭了 TCP 连接，应该停止
        }
        result = udp_handler => {
            if let Err(e) = result {
                error!("UDP 处理器错误: {}", e);
            }
        }
    }

    Ok(())
}

fn udp_associate_bind_addr(control_local_ip: Option<IpAddr>) -> SocketAddr {
    // UDP 监听地址族跟随 TCP 控制连接，避免 IPv6 客户端收到 IPv4 回复地址。
    match control_local_ip {
        Some(IpAddr::V6(_)) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    }
}

pub fn resolve_udp_associate_reply_addr(
    bind_addr: SocketAddr,
    control_local_ip: Option<IpAddr>,
) -> SocketAddr {
    // 若系统返回具体监听地址，直接告诉客户端即可。
    if !bind_addr.ip().is_unspecified() {
        return bind_addr;
    }

    // 绑定通配地址时，用控制连接本地 IP 或本地址族 localhost 生成可用回复。
    let bind_is_v4 = bind_addr.is_ipv4();
    let fallback_ip = if bind_is_v4 {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    };

    let reply_ip = control_local_ip
        .filter(|ip| ip.is_ipv4() == bind_is_v4)
        .unwrap_or(fallback_ip);

    SocketAddr::new(reply_ip, bind_addr.port())
}

async fn process_udp_traffic(
    udp_socket: Arc<UdpSocket>,
    udp_sessions: Arc<YamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
    capture_server_addr: SocketAddr,
    packet_capture: PacketCaptureController,
) -> Result<()> {
    let mut buf = [0u8; 65535];
    // Only this task owns the flow map. A worker returns its key through
    // `closed_rx`, so neither lookup nor cleanup needs a DashMap shard lock.
    let mut streams = HashMap::<DirectUdpFlowKey, tokio::sync::mpsc::Sender<Vec<u8>>>::new();
    let (closed_tx, mut closed_rx) = tokio::sync::mpsc::unbounded_channel();
    let udp_relay = SocksUdpRelay::spawn(
        udp_sessions.clone(),
        udp_socket.clone(),
        capture_server_addr,
        packet_capture.clone(),
    );

    loop {
        tokio::select! {
            Some(key) = closed_rx.recv() => {
                streams.remove(&key);
            }
            received = udp_socket.recv_from(&mut buf) => {
                // SOCKS5 UDP 是无连接的，这里按 client + target 建立/复用会话任务。
                let (n, client_addr) = received.map_err(|error| AgentError::Socks5(error.to_string()))?;
        let packet_data = &buf[..n];
        packet_capture.record_udp_payload(client_addr, capture_server_addr, packet_data);
        // 解析 SOCKS5 UDP 头部
        if n < 10 {
            continue;
        }
        if packet_data[0] != 0 || packet_data[1] != 0 {
            continue;
        }
        if packet_data[2] != 0 {
            continue;
        }
        let address_result = parse_udp_address(&packet_data[3..]);
        let (dest_addr, header_len) = match address_result {
            Ok(res) => res,
            Err(e) => {
                error!("解析 UDP 目标地址失败: {}", e);
                continue;
            }
        };
        let payload = packet_data[3 + header_len..].to_vec();
        if !direct_checker.is_direct(&dest_addr) {
            // 代理路径不维护逐目标 direct stream，直接交给共享 relay。
            udp_relay.send(client_addr, dest_addr, payload).await;
            continue;
        }

        let key = DirectUdpFlowKey::new(client_addr, dest_addr);
        let sender = streams.entry(key.clone()).or_insert_with(|| {
            spawn_direct_udp_flow(
                key,
                udp_socket.clone(),
                capture_server_addr,
                packet_capture.clone(),
                closed_tx.clone(),
            )
        });
        if sender.try_send(payload).is_err() {
            debug!("直连 SOCKS5 UDP 会话队列不可用，丢弃一个数据包");
        }
            }
        }
    }
}

pub(super) fn parse_udp_address(buf: &[u8]) -> Result<(Address, usize)> {
    // 解析 SOCKS5 UDP request header 中的 ATYP + DST.ADDR + DST.PORT。
    if buf.is_empty() {
        return Err(AgentError::Socks5("无效的 UDP 头部".to_string()));
    }
    let atyp = buf[0];
    match atyp {
        1 => {
            if buf.len() < 7 {
                return Err(AgentError::Socks5("无效的 IPv4 地址".to_string()));
            }
            let mut ip_bytes = [0u8; 4];
            ip_bytes.copy_from_slice(&buf[1..5]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((
                Address::Ipv4 {
                    addr: ip_bytes,
                    port,
                },
                7,
            ))
        }
        3 => {
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 {
                return Err(AgentError::Socks5("无效的域名地址".to_string()));
            }
            let domain = String::from_utf8_lossy(&buf[2..2 + len]).to_string();
            let port = u16::from_be_bytes([buf[2 + len], buf[2 + len + 1]]);
            Ok((Address::Domain { host: domain, port }, 2 + len + 2))
        }
        4 => {
            if buf.len() < 19 {
                return Err(AgentError::Socks5("无效的 IPv6 地址".to_string()));
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((
                Address::Ipv6 {
                    addr: ip_bytes,
                    port,
                },
                19,
            ))
        }
        _ => Err(AgentError::Socks5("不支持的地址类型".to_string())),
    }
}

pub(super) fn create_udp_packet(addr: &Address, data: &[u8]) -> Result<Vec<u8>> {
    // 创建发回客户端的 SOCKS5 UDP response packet。
    let mut packet = Vec::with_capacity(10 + data.len());
    packet.extend_from_slice(&[0, 0, 0]);
    match addr {
        Address::Ipv4 { addr, port } => {
            packet.push(1);
            packet.extend_from_slice(addr);
            packet.extend_from_slice(&port.to_be_bytes());
        }
        Address::Domain { host, port } => {
            packet.push(3);
            if host.len() > 255 {
                return Err(AgentError::Socks5("域名过长".to_string()));
            }
            packet.push(host.len() as u8);
            packet.extend_from_slice(host.as_bytes());
            packet.extend_from_slice(&port.to_be_bytes());
        }
        Address::Ipv6 { addr, port } => {
            packet.push(4);
            packet.extend_from_slice(addr);
            packet.extend_from_slice(&port.to_be_bytes());
        }
        Address::ProxyDns { .. } => {
            return Err(AgentError::Socks5(
                "SOCKS5 UDP 不支持 proxy DNS 虚拟地址".to_string(),
            ));
        }
        Address::UdpRelay => {
            return Err(AgentError::Socks5(
                "SOCKS5 UDP 不支持 UDP relay 虚拟地址".to_string(),
            ));
        }
    }
    packet.extend_from_slice(data);
    Ok(packet)
}
