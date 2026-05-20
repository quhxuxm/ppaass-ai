use crate::connection_pool::{ConnectedStream, ConnectionPool};
use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::{AgentError, Result};
use crate::telemetry;
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

#[instrument(skip(stream, pool, direct_checker))]
pub async fn handle_socks5_connection(
    stream: TcpStream,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    info!("处理 SOCKS5 连接");
    // UDP ASSOCIATE 回复地址尽量沿用 TCP 控制连接的本地地址族。
    let control_local_ip = stream.local_addr().ok().map(|addr| addr.ip());

    // 使用新的 fast-socks5 1.0 API 和 Socks5ServerProtocol
    let protocol: Socks5ServerProtocol<TcpStream, Opened> = Socks5ServerProtocol::start(stream);

    // 协商认证 - 为简单起见使用无认证方式
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
            handle_tcp_connect(protocol, target_addr, pool, direct_checker).await
        }
        // BIND 让 agent 监听一个端口等待远端主动连入。
        Socks5Command::TCPBind => {
            handle_tcp_bind(protocol, target_addr, pool, direct_checker).await
        }
        // UDP ASSOCIATE 通过 TCP 控制连接维持 UDP 会话生命周期。
        Socks5Command::UDPAssociate => {
            handle_udp_associate(
                protocol,
                target_addr,
                pool,
                control_local_ip,
                direct_checker,
            )
            .await
        }
    }
}

async fn handle_tcp_connect(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    target_addr: TargetAddr,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    let target_label = format_target_addr(&target_addr);

    // 将目标地址转换为协议 Address
    let address = convert_target_addr(&target_addr);

    if direct_checker.is_direct(&address) {
        // === 直连路径 ===
        let target_str = address_to_string(&address);
        info!("SOCKS5 CONNECT 使用直连连接到 {}", target_str);

        match TcpStream::connect(&target_str).await {
            Ok(mut target_stream) => {
                // SOCKS5 要先回复成功，客户端才会开始发送 TCP payload。
                let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
                let mut client_stream = protocol
                    .reply_success(bind_addr)
                    .await
                    .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

                info!("SOCKS5 直连隧道已建立，开始数据中继");

                match tokio::io::copy_bidirectional(&mut client_stream, &mut target_stream).await {
                    Ok((client_to_target, target_to_client)) => {
                        info!(
                            "直连 SOCKS5 中继完成: {} 字节发出, {} 字节接收",
                            client_to_target, target_to_client
                        );
                        telemetry::emit_traffic(
                            "SOCKS5 CONNECT (direct)",
                            target_label,
                            client_to_target,
                            target_to_client,
                        );
                    }
                    Err(e) => {
                        debug!("直连 SOCKS5 中继结束: {}", e);
                    }
                }
                Ok(())
            }
            Err(e) => {
                error!("直连到 {} 失败: {}", target_str, e);
                let _ = protocol.reply_error(&ReplyError::HostUnreachable).await;
                Err(AgentError::Connection(format!("直连失败: {}", e)))
            }
        }
    } else {
        // === 代理路径 ===
        let connected_stream = match pool
            .as_ref()
            .get_connected_stream(address, TransportProtocol::Tcp)
            .await
        {
            Ok(stream) => {
                info!("从连接池获取已连接流, stream_id: {}", stream.stream_id());
                stream
            }
            Err(e) => {
                error!("从连接池获取流失败: {}", e);
                let _ = protocol.reply_error(&ReplyError::HostUnreachable).await;
                return Err(e);
            }
        };

        // 发送成功回复，使用虚拟绑定地址
        // 代理路径中真实出口在 proxy 端，agent 本地只返回占位绑定地址。
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut client_stream = protocol
            .reply_success(bind_addr)
            .await
            .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

        info!("SOCKS5 隧道已建立，开始数据中继");

        // 启动双向数据中继
        relay_data(
            &mut client_stream,
            connected_stream,
            "SOCKS5 CONNECT",
            target_label,
        )
        .await
    }
}

async fn handle_tcp_bind(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    target_addr: TargetAddr,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    info!("处理 SOCKS5 BIND 命令，目标: {:?}", target_addr);
    let target_label = format_target_addr(&target_addr);

    // 将目标地址转换为协议 Address
    let address = convert_target_addr(&target_addr);

    // 在随机端口上绑定 TCP 套接字以接受传入连接
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .map_err(|e| AgentError::Socks5(format!("绑定 TCP 套接字失败: {}", e)))?;

    let bind_addr = listener
        .local_addr()
        .map_err(|e| AgentError::Socks5(format!("获取本地地址失败: {}", e)))?;

    info!("SOCKS5 BIND 监听在 {}", bind_addr);

    // 发送第一个成功回复，包含绑定地址
    let _tcp_stream = protocol
        .reply_success(bind_addr)
        .await
        .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

    // 等待绑定地址上的传入连接
    // BIND 不应无限等待远端连接，超时后释放监听端口。
    match tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept()).await {
        Ok(Ok((mut incoming_stream, peer_addr))) => {
            info!(
                "SOCKS5 BIND: 接受来自 {} 的连接，目标 {:?}",
                peer_addr, address
            );

            if direct_checker.is_direct(&address) {
                // === 直连路径 ===
                let target_str = address_to_string(&address);
                info!("SOCKS5 BIND 使用直连连接到 {}", target_str);

                match TcpStream::connect(&target_str).await {
                    Ok(mut target_stream) => {
                        info!("SOCKS5 BIND 直连隧道已建立，开始数据中继");
                        match tokio::io::copy_bidirectional(
                            &mut incoming_stream,
                            &mut target_stream,
                        )
                        .await
                        {
                            Ok((c2t, t2c)) => {
                                info!(
                                    "直连 SOCKS5 BIND 中继完成: {} 字节发出, {} 字节接收",
                                    c2t, t2c
                                );
                                telemetry::emit_traffic(
                                    "SOCKS5 BIND (direct)",
                                    target_label,
                                    c2t,
                                    t2c,
                                );
                            }
                            Err(e) => {
                                debug!("直连 SOCKS5 BIND 中继结束: {}", e);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => {
                        error!("直连到目标失败: {}", e);
                        Err(AgentError::Connection(format!("直连失败: {}", e)))
                    }
                }
            } else {
                // === 代理路径 ===
                let connected_stream = match pool
                    .as_ref()
                    .get_connected_stream(address, TransportProtocol::Tcp)
                    .await
                {
                    Ok(stream) => {
                        info!("从连接池获取已连接流, stream_id: {}", stream.stream_id());
                        stream
                    }
                    Err(e) => {
                        error!("从连接池获取流失败: {}", e);
                        return Err(e);
                    }
                };

                info!("SOCKS5 BIND 隧道已建立，开始数据中继");

                relay_data(
                    &mut incoming_stream,
                    connected_stream,
                    "SOCKS5 BIND",
                    target_label,
                )
                .await
            }
        }
        Ok(Err(e)) => {
            error!("接受传入连接失败: {}", e);
            Err(AgentError::Socks5(format!("接受连接失败: {}", e)))
        }
        Err(_) => {
            error!("SOCKS5 BIND: 等待传入连接超时");
            Err(AgentError::Socks5("等待传入连接超时".to_string()))
        }
    }
}

async fn handle_udp_associate(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    _target_addr: TargetAddr,
    pool: Arc<ConnectionPool>,
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
    let pool = pool.clone();

    // 客户端向 `bind_addr` 发送 UDP 数据包

    // 需要保持 TCP 流存活以维持关联
    let keep_alive = async move {
        let mut buf = [0u8; 1];
        // 如果 read 返回 0（EOF）或错误，表示客户端已关闭连接
        let _ = tcp_stream.read(&mut buf).await;
        debug!("UDP 关联 TCP 控制通道已关闭");
    };

    let udp_handler = process_udp_traffic(udp_socket, pool, direct_checker);

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

fn resolve_udp_associate_reply_addr(
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
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    let mut buf = [0u8; 65535];
    type StreamMap = DashMap<String, Sender<Vec<u8>>>;
    let streams: Arc<StreamMap> = Arc::new(DashMap::new());
    let udp_relay = SocksUdpRelay::spawn(pool.clone(), udp_socket.clone());

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

const SOCKS_UDP_RELAY_CHANNEL_SIZE: usize = 4096;
const SOCKS_UDP_RELAY_CONNECTION_IDLE: Duration = Duration::from_secs(30);

struct SocksUdpRelay {
    tx: tokio::sync::mpsc::Sender<SocksUdpRelayRequest>,
}

#[derive(Clone)]
struct SocksUdpRelayRequest {
    client: SocketAddr,
    target: Address,
    packet: Vec<u8>,
}

#[derive(Clone, Debug, Eq)]
struct SocksUdpFlowKey {
    client: SocketAddr,
    target: String,
}

impl PartialEq for SocksUdpFlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.client == other.client && self.target == other.target
    }
}

impl Hash for SocksUdpFlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.client.hash(state);
        self.target.hash(state);
    }
}

struct SocksUdpRelayState {
    flow_ids: HashMap<SocksUdpFlowKey, u64>,
    flows: HashMap<u64, (SocketAddr, Address)>,
    next_flow_id: u64,
}

impl SocksUdpRelayState {
    fn new() -> Self {
        Self {
            flow_ids: HashMap::new(),
            flows: HashMap::new(),
            next_flow_id: 1,
        }
    }

    fn flow_id(&mut self, client: SocketAddr, target: &Address) -> u64 {
        let key = SocksUdpFlowKey {
            client,
            target: format!("{target:?}"),
        };
        if let Some(id) = self.flow_ids.get(&key) {
            return *id;
        }

        let id = self.next_available_flow_id();
        self.flow_ids.insert(key, id);
        self.flows.insert(id, (client, target.clone()));
        id
    }

    fn flow(&self, flow_id: u64) -> Option<&(SocketAddr, Address)> {
        self.flows.get(&flow_id)
    }

    fn next_available_flow_id(&mut self) -> u64 {
        loop {
            let id = self.next_flow_id;
            self.next_flow_id = self.next_flow_id.wrapping_add(1).max(1);
            if !self.flows.contains_key(&id) {
                return id;
            }
        }
    }
}

impl SocksUdpRelay {
    fn spawn(pool: Arc<ConnectionPool>, udp_socket: Arc<UdpSocket>) -> Arc<Self> {
        let (tx, rx) = tokio::sync::mpsc::channel(SOCKS_UDP_RELAY_CHANNEL_SIZE);
        tokio::spawn(run_socks_udp_relay(pool, udp_socket, rx));
        Arc::new(Self { tx })
    }

    async fn send(&self, client: SocketAddr, target: Address, packet: Vec<u8>) {
        if self
            .tx
            .send(SocksUdpRelayRequest {
                client,
                target,
                packet,
            })
            .await
            .is_err()
        {
            debug!("SOCKS5 UDP 共享转发器已关闭，丢弃请求");
        }
    }
}

async fn run_socks_udp_relay(
    pool: Arc<ConnectionPool>,
    udp_socket: Arc<UdpSocket>,
    mut rx: tokio::sync::mpsc::Receiver<SocksUdpRelayRequest>,
) {
    let mut state = SocksUdpRelayState::new();
    let mut retry_request = None;
    let mut reconnect_delay = Duration::from_millis(200);

    loop {
        let first_request = match retry_request.take() {
            Some(request) => request,
            None => {
                let Some(request) = rx.recv().await else {
                    break;
                };
                request
            }
        };

        let connected = connect_socks_udp_relay_stream(&pool).await;
        let proxy_io = match connected {
            Ok(proxy_io) => {
                reconnect_delay = Duration::from_millis(200);
                proxy_io
            }
            Err(e) => {
                warn!("SOCKS5 UDP 共享连接创建失败：{e}");
                tokio::time::sleep(reconnect_delay).await;
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                retry_request = Some(first_request);
                continue;
            }
        };

        info!("SOCKS5 UDP 已建立共享 proxy 连接");
        let (mut reader, mut writer) = tokio::io::split(proxy_io);
        let idle = tokio::time::sleep(SOCKS_UDP_RELAY_CONNECTION_IDLE);
        tokio::pin!(idle);
        retry_request = Some(first_request);
        let mut response_buf = vec![0u8; 65535];

        loop {
            if let Some(request) = retry_request.take() {
                if let Err(e) = send_socks_udp_request(&mut writer, &mut state, &request).await {
                    debug!("SOCKS5 UDP 共享连接写入失败：{e}");
                    retry_request = Some(request);
                    break;
                }
                idle.as_mut()
                    .reset(tokio::time::Instant::now() + SOCKS_UDP_RELAY_CONNECTION_IDLE);
                continue;
            }

            tokio::select! {
                maybe_request = rx.recv() => {
                    let Some(request) = maybe_request else {
                        let _ = writer.shutdown().await;
                        return;
                    };
                    if let Err(e) = send_socks_udp_request(&mut writer, &mut state, &request).await {
                        debug!("SOCKS5 UDP 共享连接写入失败：{e}");
                        retry_request = Some(request);
                        break;
                    }
                    idle.as_mut().reset(tokio::time::Instant::now() + SOCKS_UDP_RELAY_CONNECTION_IDLE);
                }
                _ = &mut idle => {
                    debug!(
                        "SOCKS5 UDP 共享连接空闲超过 {} 秒，主动关闭 proxy 连接",
                        SOCKS_UDP_RELAY_CONNECTION_IDLE.as_secs()
                    );
                    let _ = writer.shutdown().await;
                    break;
                }
                read = reader.read(&mut response_buf) => {
                    match read {
                        Ok(0) => {
                            debug!("SOCKS5 UDP 共享连接已关闭");
                            break;
                        }
                        Ok(n) => {
                            if let Err(e) = handle_socks_udp_response(
                                &udp_socket,
                                &state,
                                &response_buf[..n],
                            ).await {
                                debug!("SOCKS5 UDP 回复写回失败：{e}");
                            }
                            idle.as_mut().reset(tokio::time::Instant::now() + SOCKS_UDP_RELAY_CONNECTION_IDLE);
                        }
                        Err(e) => {
                            debug!("SOCKS5 UDP 共享连接读取失败：{e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    debug!("SOCKS5 UDP 共享转发器退出");
}

async fn connect_socks_udp_relay_stream(
    pool: &ConnectionPool,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    let connected = pool
        .get_connected_stream(Address::UdpRelay, TransportProtocol::Udp)
        .await?;
    Ok(connected.into_async_io())
}

async fn send_socks_udp_request<W>(
    writer: &mut W,
    state: &mut SocksUdpRelayState,
    request: &SocksUdpRelayRequest,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let flow_id = state.flow_id(request.client, &request.target);
    let packet = UdpRelayPacket {
        flow_id,
        address: request.target.clone(),
        data: request.packet.clone(),
    }
    .encode()
    .map_err(std::io::Error::other)?;

    writer.write_all(&packet).await?;
    writer.flush().await
}

async fn handle_socks_udp_response(
    udp_socket: &UdpSocket,
    state: &SocksUdpRelayState,
    response: &[u8],
) -> std::io::Result<()> {
    let packet = UdpRelayPacket::decode(response).map_err(std::io::Error::other)?;
    let Some((client, target)) = state.flow(packet.flow_id) else {
        debug!("SOCKS5 UDP 收到无匹配 flow 的回复 id={}", packet.flow_id);
        return Ok(());
    };

    let response = create_udp_packet(target, &packet.data).map_err(std::io::Error::other)?;
    udp_socket.send_to(&response, client).await?;
    Ok(())
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

async fn relay_data(
    client_stream: &mut TcpStream,
    connected_stream: ConnectedStream,
    protocol: &str,
    target: String,
) -> Result<()> {
    // 转换为 AsyncRead + AsyncWrite 兼容类型
    let mut proxy_io = connected_stream.into_async_io();

    // 使用 tokio 优化的双向拷贝
    // 比手动 select 循环更高效：
    // 1. 尽可能使用零拷贝
    // 2. 优化的缓冲区
    // 3. 正确处理背压
    match tokio::io::copy_bidirectional(client_stream, &mut proxy_io).await {
        Ok((client_to_proxy, proxy_to_client)) => {
            info!(
                "SOCKS5 中继完成: {} 字节 客户端->代理, {} 字节 代理->客户端",
                client_to_proxy, proxy_to_client
            );
            telemetry::emit_traffic(protocol, target, client_to_proxy, proxy_to_client);
        }
        Err(e) => {
            // 客户端关闭连接时出现的连接错误是预期的
            debug!("SOCKS5 中继结束: {}", e);
        }
    }

    Ok(())
}

fn parse_udp_address(buf: &[u8]) -> Result<(Address, usize)> {
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

fn create_udp_packet(addr: &Address, data: &[u8]) -> Result<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_udp_reply_uses_control_ip_for_unspecified_bind_addr() {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53000);
        let control_local_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let reply_addr = resolve_udp_associate_reply_addr(bind_addr, control_local_ip);

        assert_eq!(
            reply_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000)
        );
    }

    #[test]
    fn resolve_udp_reply_keeps_specific_bind_addr() {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 53000);
        let control_local_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let reply_addr = resolve_udp_associate_reply_addr(bind_addr, control_local_ip);

        assert_eq!(reply_addr, bind_addr);
    }

    #[test]
    fn resolve_udp_reply_uses_family_safe_fallback() {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53000);
        let control_local_ip = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));

        let reply_addr = resolve_udp_associate_reply_addr(bind_addr, control_local_ip);

        assert_eq!(
            reply_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000)
        );
    }
}
