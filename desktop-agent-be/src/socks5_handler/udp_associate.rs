use super::udp_relay::SocksUdpRelay;
use super::*;

pub(super) async fn handle_udp_associate(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    _target_addr: TargetAddr,
    udp_pool: Arc<ConnectionPool>,
    control_local_ip: Option<IpAddr>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    info!("处理 UDP ASSOCIATE");

    // 在随机端口上绑定 UDP 套接字
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
    let udp_pool = udp_pool.clone();

    // 客户端向 `bind_addr` 发送 UDP 数据包

    // 需要保持 TCP 流存活以维持关联
    let keep_alive = async move {
        let mut buf = [0u8; 1];
        // 如果 read 返回 0（EOF）或错误，表示客户端已关闭连接
        let _ = tcp_stream.read(&mut buf).await;
        debug!("UDP 关联 TCP 控制通道已关闭");
    };

    let udp_handler = process_udp_traffic(udp_socket, udp_pool, direct_checker);

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

pub(super) fn resolve_udp_associate_reply_addr(
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
    udp_pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    let mut buf = [0u8; 65535];
    type StreamMap = DashMap<String, Sender<Vec<u8>>>;
    let streams: Arc<StreamMap> = Arc::new(DashMap::new());
    let udp_relay = SocksUdpRelay::spawn(udp_pool.clone(), udp_socket.clone());

    loop {
        // SOCKS5 UDP 是无连接的，这里按目标地址建立/复用会话任务。
        let (n, client_addr) = udp_socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| AgentError::Socks5(e.to_string()))?;
        let packet_data = &buf[..n];
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
        let dest_key = format!("{:?}", dest_addr);
        debug!("解析 UDP 目标地址: {:?}", dest_addr);
        if !streams.contains_key(&dest_key) {
            // 首次看到目标时创建对应的直连或代理 UDP 会话。
            info!("新的 UDP 会话，目标: {:?}", dest_addr);

            if direct_checker.is_direct(&dest_addr) {
                // === 直连 UDP 路径 ===
                let target_str = address_to_string(&dest_addr);
                info!("UDP 会话使用直连连接到 {}", target_str);

                let (tx, mut rx) = channel::<Vec<u8>>(32);
                streams.insert(dest_key.clone(), tx);
                let udp_client = udp_socket.clone();
                let dest_addr_clone = dest_addr.clone();
                let streams_clone = streams.clone();
                let dest_key_clone = dest_key.clone();

                tokio::spawn(async move {
                    // 绑定本地 UDP 套接字并直连目标
                    let target_socket = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("绑定直连 UDP 套接字失败: {}", e);
                            streams_clone.remove(&dest_key_clone);
                            return;
                        }
                    };
                    if let Err(e) = target_socket.connect(&target_str).await {
                        error!("直连 UDP 套接字连接到 {} 失败: {}", target_str, e);
                        streams_clone.remove(&dest_key_clone);
                        return;
                    }

                    // 客户端到目标方向：channel 收到 payload 后发给直连 UDP socket。
                    let write_task = async {
                        while let Some(data) = rx.recv().await {
                            trace!(
                                "直连 UDP 发送到目标: {:?}\n{}",
                                dest_addr_clone,
                                pretty_hex::pretty_hex(&data)
                            );
                            if let Err(e) = target_socket.send(&data).await {
                                debug!("直连 UDP 发送错误: {}", e);
                                break;
                            }
                        }
                    };

                    // 目标到客户端方向：目标回复重新封装 SOCKS5 UDP 头后发回客户端。
                    let read_task = async {
                        let mut read_buf = [0u8; 65535];
                        loop {
                            match target_socket.recv(&mut read_buf).await {
                                Ok(len) => {
                                    let data = &read_buf[..len];
                                    trace!(
                                        "直连 UDP 从目标接收: {:?}\n{}",
                                        dest_addr_clone,
                                        pretty_hex::pretty_hex(&data)
                                    );
                                    match create_udp_packet(&dest_addr_clone, data) {
                                        Ok(packet) => {
                                            if let Err(e) =
                                                udp_client.send_to(&packet, client_addr).await
                                            {
                                                error!("发送 UDP 数据包到客户端失败: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            error!("创建 UDP 数据包失败: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!("直连 UDP 接收错误: {}", e);
                                    break;
                                }
                            }
                        }
                    };

                    tokio::select! {
                        _ = write_task => {}
                        _ = read_task => {}
                    }
                    streams_clone.remove(&dest_key_clone);
                    info!("直连 UDP 会话结束: {:?}", dest_addr_clone);
                });
            } else {
                udp_relay
                    .send(client_addr, dest_addr.clone(), payload)
                    .await;
                continue;
            }
        }
        // 当前 datagram 投递给目标会话；若会话刚创建，首包也会走这里。
        let sender = streams.get(&dest_key).map(|s| s.clone());
        if let Some(sender) = sender {
            let _ = sender.send(payload).await;
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
        Address::TcpYamux => {
            return Err(AgentError::Socks5(
                "SOCKS5 UDP 不支持 TCP Yamux 虚拟地址".to_string(),
            ));
        }
        Address::UdpYamux => {
            return Err(AgentError::Socks5(
                "SOCKS5 UDP 不支持 UDP Yamux 虚拟地址".to_string(),
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
