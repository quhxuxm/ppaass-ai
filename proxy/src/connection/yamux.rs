//! Yamux 子流处理。
//!
//! 外层 session 只负责复用连接；每个子流打开后，第一帧仍然是一个小的
//! `ConnectRequest` 控制帧，用来说明这个子流要连哪个真实目标。
//! 连接成功后，子流本身就变成 agent 与目标之间的裸字节通道。

use super::target::target_addr_for_address;
use super::udp_relay_flow::{
    QueuedUdpRelayResponse, UDP_RELAY_RESPONSE_BATCH_LIMIT, UdpRelayFlowChannels, UdpRelayFlowSet,
    udp_relay_channel_size,
};
use super::*;

pub(super) async fn handle_yamux_tcp_stream(
    mut stream: StreamHandle,
    proxy_config: Arc<ProxyConfig>,
    egress_state: Arc<EgressState>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    username: Option<String>,
) -> Result<()> {
    // 子流控制帧不走 ProxyCodec，而是直接在 Yamux stream 内用长度前缀写 ConnectRequest。
    let connect_request = read_yamux_connect_request(&mut stream).await?;
    debug!(
        "[Yamux 连接请求] 请求 ID={}，地址={:?}，传输协议={:?}",
        connect_request.request_id, connect_request.address, connect_request.transport
    );

    if connect_request.transport != TransportProtocol::Tcp {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Yamux substream only supports TCP transport".to_string(),
        )
        .await?;
        return Ok(());
    }

    if matches!(
        connect_request.address,
        Address::TcpYamux | Address::UdpYamux | Address::UdpRelay
    ) {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Yamux substream target must be a TCP address".to_string(),
        )
        .await?;
        return Ok(());
    }

    if let Some(username) = &username
        && !bandwidth_monitor.check_limit(username).await
    {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Bandwidth limit exceeded".to_string(),
        )
        .await?;
        return Ok(());
    }

    if proxy_config.forward_mode {
        // forward 模式下子流不直连目标，而是把子流接到下一跳 proxy 的 ClientStream。
        return handle_yamux_upstream_connect(stream, connect_request, proxy_config).await;
    }

    let target_addr = match target_addr_for_address(&proxy_config, &connect_request.address) {
        Ok(target_addr) => target_addr,
        Err(err) => {
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!("Failed to resolve target: {err}"),
            )
            .await?;
            return Ok(());
        }
    };

    let connect_timeout = Duration::from_secs(proxy_config.connect_timeout_secs);
    match tokio::time::timeout(connect_timeout, egress_state.connect_tcp(&target_addr)).await {
        Ok(Ok(target_stream)) => {
            debug!(
                "已通过 Yamux 子流连接目标（TCP）：{}，出站设备={}",
                target_addr,
                proxy_config
                    .outbound_interface
                    .as_deref()
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or("默认路由")
            );
            send_yamux_connect_success(&mut stream, connect_request.request_id, "Connected")
                .await?;
            relay_yamux_tcp_stream(
                stream,
                target_stream,
                proxy_config.yamux_tcp_relay_idle_timeout_secs,
                proxy_config.tcp_relay_buffer_size(),
            )
            .await?;
        }
        Ok(Err(e)) => {
            warn!("Yamux 子流连接目标失败（TCP）：{}，目标={}", e, target_addr);
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!("Failed to connect: {}", e),
            )
            .await?;
        }
        Err(_) => {
            warn!(
                "Yamux 子流连接目标超时（TCP）：目标={}，超时={} 秒",
                target_addr, proxy_config.connect_timeout_secs
            );
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!(
                    "Connect timeout after {} seconds",
                    proxy_config.connect_timeout_secs
                ),
            )
            .await?;
        }
    }

    Ok(())
}

pub(super) async fn handle_yamux_udp_stream(
    mut stream: StreamHandle,
    proxy_config: Arc<ProxyConfig>,
    egress_state: Arc<EgressState>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    username: Option<String>,
    connection_limiter: ConnectionLimiter,
) -> Result<()> {
    // UDP Yamux 子流也先读 ConnectRequest；后续根据目标类型进入单目标 UDP 或共享 UDP relay。
    let connect_request = read_yamux_connect_request(&mut stream).await?;
    debug!(
        "[Yamux UDP 连接请求] 请求 ID={}，地址={:?}，传输协议={:?}",
        connect_request.request_id, connect_request.address, connect_request.transport
    );

    if connect_request.transport != TransportProtocol::Udp {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Yamux UDP substream only supports UDP transport".to_string(),
        )
        .await?;
        return Ok(());
    }

    if matches!(
        connect_request.address,
        Address::TcpYamux | Address::UdpYamux
    ) {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Yamux UDP substream target must not be a Yamux outer address".to_string(),
        )
        .await?;
        return Ok(());
    }

    if let Some(username) = &username
        && !bandwidth_monitor.check_limit(username).await
    {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Bandwidth limit exceeded".to_string(),
        )
        .await?;
        return Ok(());
    }

    if proxy_config.forward_mode {
        match UpstreamConnection::connect(
            &proxy_config,
            connect_request.address.clone(),
            connect_request.transport,
        )
        .await
        {
            Ok(upstream_conn) => {
                send_yamux_connect_success(
                    &mut stream,
                    connect_request.request_id,
                    "Connected through upstream",
                )
                .await?;
                relay_yamux_udp_byte_stream(
                    stream,
                    upstream_conn.into_stream(),
                    proxy_config.udp_relay_idle_timeout_secs,
                )
                .await?;
            }
            Err(e) => {
                error!("Yamux UDP 子流连接上游代理失败：{}", e);
                send_yamux_connect_error(
                    &mut stream,
                    connect_request.request_id,
                    format!("Upstream error: {}", e),
                )
                .await?;
            }
        }
        return Ok(());
    }

    if matches!(connect_request.address, Address::UdpRelay) {
        // 在 UDP Yamux 内再承载共享 UDP relay，用于让一个子流复用多个 UDP flow。
        send_yamux_connect_success(
            &mut stream,
            connect_request.request_id,
            "UDP relay connected",
        )
        .await?;
        relay_yamux_udp_relay_stream(
            stream,
            proxy_config,
            egress_state,
            bandwidth_monitor,
            username,
            connection_limiter,
        )
        .await?;
        return Ok(());
    }

    let target_addr = match target_addr_for_address(&proxy_config, &connect_request.address) {
        Ok(target_addr) => target_addr,
        Err(err) => {
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!("Failed to resolve target: {err}"),
            )
            .await?;
            return Ok(());
        }
    };

    let connect_timeout = Duration::from_secs(proxy_config.connect_timeout_secs);
    match tokio::time::timeout(connect_timeout, egress_state.connect_udp(&target_addr)).await {
        Ok(Ok(socket)) => {
            debug!(
                "已通过 Yamux 子流连接目标（UDP）：{}，出站设备={}",
                target_addr,
                proxy_config
                    .outbound_interface
                    .as_deref()
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or("默认路由")
            );
            send_yamux_connect_success(&mut stream, connect_request.request_id, "Connected")
                .await?;
            relay_yamux_udp_stream(stream, socket, proxy_config.udp_relay_idle_timeout_secs)
                .await?;
        }
        Ok(Err(e)) => {
            warn!("Yamux 子流连接目标失败（UDP）：{}，目标={}", e, target_addr);
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!("Failed to connect UDP: {}", e),
            )
            .await?;
        }
        Err(_) => {
            warn!(
                "Yamux 子流连接目标超时（UDP）：目标={}，超时={} 秒",
                target_addr, proxy_config.connect_timeout_secs
            );
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!(
                    "Connect timeout after {} seconds",
                    proxy_config.connect_timeout_secs
                ),
            )
            .await?;
        }
    }

    Ok(())
}

async fn handle_yamux_upstream_connect(
    mut stream: StreamHandle,
    connect_request: ConnectRequest,
    proxy_config: Arc<ProxyConfig>,
) -> Result<()> {
    debug!("正在将 Yamux 子流请求转发到上游代理");
    match UpstreamConnection::connect(
        &proxy_config,
        connect_request.address.clone(),
        connect_request.transport,
    )
    .await
    {
        Ok(upstream_conn) => {
            send_yamux_connect_success(
                &mut stream,
                connect_request.request_id,
                "Connected through upstream",
            )
            .await?;
            relay_yamux_tcp_stream(
                stream,
                upstream_conn.into_stream(),
                proxy_config.yamux_tcp_relay_idle_timeout_secs,
                proxy_config.tcp_relay_buffer_size(),
            )
            .await?;
        }
        Err(e) => {
            error!("Yamux 子流连接上游代理失败：{}", e);
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!("Upstream error: {}", e),
            )
            .await?;
        }
    }

    Ok(())
}

async fn relay_yamux_tcp_stream<S>(
    mut agent_stream: StreamHandle,
    mut target_stream: S,
    idle_timeout_secs: u64,
    relay_buffer_size: usize,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // Yamux 子流天然就是 AsyncRead/AsyncWrite，所以 TCP 路径可直接与目标流双向拷贝。
    if idle_timeout_secs == 0 {
        match tokio::io::copy_bidirectional_with_sizes(
            &mut agent_stream,
            &mut target_stream,
            relay_buffer_size,
            relay_buffer_size,
        )
        .await
        {
            Ok((up, down)) => debug!(
                "Yamux 子流中继已结束：上行 {}，下行 {}，buffer={} bytes",
                up, down, relay_buffer_size
            ),
            Err(e) => debug!("Yamux 子流中继错误：{}", e),
        }
        return Ok(());
    }

    let idle_timeout = Duration::from_secs(idle_timeout_secs);
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_stream);
    let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;
    let mut agent_buf = vec![0u8; relay_buffer_size];
    let mut target_buf = vec![0u8; relay_buffer_size];

    loop {
        tokio::select! {
            _ = &mut idle => {
                debug!(
                    "Yamux TCP 子流空闲超过 {} 秒，关闭连接",
                    idle_timeout.as_secs()
                );
                break;
            }
            read = agent_reader.read(&mut agent_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        up_bytes += n as u64;
                        match tokio::time::timeout(idle_timeout, async {
                            target_writer.write_all(&agent_buf[..n]).await?;
                            target_writer.flush().await
                        }).await {
                            Ok(Ok(())) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux TCP relay 写入目标失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux TCP relay 写入目标超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux TCP relay 读取 agent 数据失败：{}", e);
                        break;
                    }
                }
            }
            read = target_reader.read(&mut target_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        down_bytes += n as u64;
                        match tokio::time::timeout(idle_timeout, async {
                            agent_writer.write_all(&target_buf[..n]).await?;
                            agent_writer.flush().await
                        }).await {
                            Ok(Ok(())) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux TCP relay 写回 agent 失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux TCP relay 写回 agent 超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux TCP relay 读取目标数据失败：{}", e);
                        break;
                    }
                }
            }
        }
    }

    debug!(
        "Yamux 子流中继已结束：上行 {}，下行 {}，buffer={} bytes",
        up_bytes, down_bytes, relay_buffer_size
    );
    Ok(())
}

async fn relay_yamux_udp_byte_stream<S>(
    agent_stream: StreamHandle,
    mut target_stream: S,
    idle_timeout_secs: u64,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // UDP payload 需要保留数据报边界；DatagramStreamIo 在字节接口上做一层数据报封装。
    let mut agent_io = DatagramStreamIo::new(agent_stream);
    if idle_timeout_secs == 0 {
        match tokio::io::copy_bidirectional(&mut agent_io, &mut target_stream).await {
            Ok((up, down)) => debug!("Yamux UDP 字节中继已结束：上行 {}，下行 {}", up, down),
            Err(e) => debug!("Yamux UDP 字节中继错误：{}", e),
        }
        return Ok(());
    }

    let idle_timeout = Duration::from_secs(idle_timeout_secs);
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);
    let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;
    let mut agent_buf = vec![0u8; 65535];
    let mut target_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = &mut idle => {
                debug!(
                    "Yamux UDP 字节中继空闲超过 {} 秒，关闭连接",
                    idle_timeout.as_secs()
                );
                break;
            }
            read = agent_reader.read(&mut agent_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        up_bytes += n as u64;
                        match tokio::time::timeout(idle_timeout, async {
                            target_writer.write_all(&agent_buf[..n]).await?;
                            target_writer.flush().await
                        }).await {
                            Ok(Ok(())) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux UDP 字节中继写入目标失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux UDP 字节中继写入目标超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux UDP 字节中继读取 agent 数据失败：{}", e);
                        break;
                    }
                }
            }
            read = target_reader.read(&mut target_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        down_bytes += n as u64;
                        match tokio::time::timeout(idle_timeout, async {
                            agent_writer.write_all(&target_buf[..n]).await?;
                            agent_writer.flush().await
                        }).await {
                            Ok(Ok(())) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux UDP 字节中继写回 agent 失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux UDP 字节中继写回 agent 超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux UDP 字节中继读取目标数据失败：{}", e);
                        break;
                    }
                }
            }
        }
    }

    debug!(
        "Yamux UDP 字节中继已结束：上行 {}，下行 {}",
        up_bytes, down_bytes
    );
    Ok(())
}

async fn relay_yamux_udp_stream(
    agent_stream: StreamHandle,
    udp_socket: UdpSocket,
    idle_timeout_secs: u64,
) -> Result<()> {
    // 单目标 UDP：一个 Yamux 子流对应一个已 connect 的 UDP socket。
    let agent_io = DatagramStreamIo::new(agent_stream);
    let udp_socket = Arc::new(udp_socket);
    let udp_recv = udp_socket.clone();
    let udp_send = udp_socket.clone();
    let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);
    let idle_timeout = Duration::from_secs(idle_timeout_secs);
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let mut agent_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = &mut idle => {
                debug!(
                    "Yamux UDP 子流空闲超过 {} 秒，关闭 socket",
                    idle_timeout.as_secs()
                );
                break;
            }
            read = agent_reader.read(&mut agent_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        match tokio::time::timeout(idle_timeout, udp_send.send(&agent_buf[..n])).await {
                            Ok(Ok(_)) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux UDP 子流发送目标失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux UDP 子流发送目标超过 {} 秒，关闭 socket", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux UDP 子流读取 agent 数据失败：{}", e);
                        break;
                    }
                }
            }
            recv = udp_recv.recv(&mut udp_buf) => {
                match recv {
                    Ok(n) => {
                        match tokio::time::timeout(idle_timeout, async {
                            agent_writer.write_all(&udp_buf[..n]).await?;
                            agent_writer.flush().await
                        }).await {
                            Ok(Ok(())) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux UDP 子流写回 agent 失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux UDP 子流写回 agent 超过 {} 秒，关闭 socket", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux UDP 子流读取目标失败：{}", e);
                        break;
                    }
                }
            }
        }
    }

    debug!("Yamux UDP 子流已结束");
    Ok(())
}

async fn relay_yamux_udp_relay_stream(
    agent_stream: StreamHandle,
    proxy_config: Arc<ProxyConfig>,
    egress_state: Arc<EgressState>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    username: Option<String>,
    connection_limiter: ConnectionLimiter,
) -> Result<()> {
    // UDP Yamux 子流本身是字节流；`DatagramStreamIo` 在子流上加长度前缀，
    // 保留 UDP datagram 边界。这样上层 relay 每次 read/write 都对应一个完整
    // `UdpRelayPacket`，不会把多个 UDP 包粘在一起，也不会拆半包。
    let agent_io = DatagramStreamIo::new(agent_stream);
    let (mut reader, mut writer) = tokio::io::split(agent_io);
    let channel_size = udp_relay_channel_size(proxy_config.as_ref());
    let (response_tx, mut response_rx) =
        tokio::sync::mpsc::channel::<QueuedUdpRelayResponse>(channel_size);
    let (flow_done_tx, mut flow_done_rx) = tokio::sync::mpsc::channel::<u64>(channel_size);
    // 与 legacy UDP relay 共用同一个 flow 管理核心。Yamux 路径只保留两点差异：
    // 1. 从 Yamux datagram 子流读取 agent 侧 UdpRelayPacket；
    // 2. 把目标响应编码后直接写回同一个 Yamux datagram 子流。
    // UDP socket 创建、flow 上限、buffered bytes 预算和 done 清理都在 FlowSet 内部完成。
    let mut flow_set = UdpRelayFlowSet::new(
        proxy_config.as_ref(),
        egress_state,
        connection_limiter,
        UdpRelayFlowChannels {
            response_tx: response_tx.clone(),
            flow_done_tx: flow_done_tx.clone(),
        },
        "Yamux UDP relay",
        "proxy yamux udp relay flow",
    );
    let relay_idle_timeout = flow_set.idle_timeout();
    let relay_idle = tokio::time::sleep(relay_idle_timeout);
    tokio::pin!(relay_idle);
    let mut request_buf = vec![0u8; 1024 * 1024];

    loop {
        tokio::select! {
            _ = &mut relay_idle => {
                debug!(
                    "Yamux UDP 共享中继空闲超过 {} 秒，关闭该子流",
                    relay_idle_timeout.as_secs()
                );
                break;
            }
            read = reader.read(&mut request_buf) => {
                let n = match read {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        debug!("Yamux UDP 共享中继读取失败：{e}");
                        break;
                    }
                };

                relay_idle.as_mut().reset(tokio::time::Instant::now() + relay_idle_timeout);
                if let Some(user) = &username {
                    // 这里统计的是 agent -> proxy 外层 datagram 的字节数，也就是编码后的
                    // `UdpRelayPacket` 大小；与 legacy 路径保持同一口径。
                    bandwidth_monitor.record_received(user, n as u64);
                }

                let relay_packet = match UdpRelayPacket::decode(&request_buf[..n]) {
                    Ok(packet) => packet,
                    Err(e) => {
                        debug!("Yamux UDP relay 数据包解析失败：{e}");
                        continue;
                    }
                };

                flow_set.dispatch(relay_packet).await;
            }
            response = response_rx.recv() => {
                let Some(response) = response else { break };
                // Yamux 子流写回仍然可能被慢 agent 或 Yamux 窗口阻塞，所以保留
                // relay_idle_timeout 作为写超时。批量 helper 内部只做非阻塞 drain，
                // 不会在等待更多响应时卡住这里。
                match tokio::time::timeout(relay_idle_timeout, async {
                    write_yamux_udp_relay_response_batch(
                        &mut writer,
                        &mut response_rx,
                        response,
                        username.as_deref(),
                        bandwidth_monitor.as_ref(),
                    ).await
                }).await {
                    Ok(Ok(())) => {
                        relay_idle.as_mut().reset(tokio::time::Instant::now() + relay_idle_timeout);
                    }
                    Ok(Err(e)) => {
                        debug!("Yamux UDP relay 响应写回失败：{e}");
                        break;
                    }
                    Err(_) => {
                        debug!("Yamux UDP relay 响应写回超过 {} 秒，关闭该子流", relay_idle_timeout.as_secs());
                        break;
                    }
                }
            }
            done = flow_done_rx.recv() => {
                let Some(flow_id) = done else { break };
                flow_set.remove(flow_id);
            }
        }
    }

    debug!("Yamux UDP 共享中继已结束");
    Ok(())
}

async fn write_yamux_udp_relay_response_batch<W>(
    writer: &mut W,
    response_rx: &mut tokio::sync::mpsc::Receiver<QueuedUdpRelayResponse>,
    first_response: QueuedUdpRelayResponse,
    username: Option<&str>,
    bandwidth_monitor: &BandwidthMonitor,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    // 首个 response 已由 `recv().await` 拿到；随后短批量 drain 已就绪响应。
    // 和 legacy 路径一样，permit 会一直持有到本批 flush 完成，防止写缓冲中仍有
    // 数据时过早释放全局 buffered bytes 预算。
    let first_buffer_permit =
        write_yamux_udp_relay_response(writer, first_response, username, bandwidth_monitor).await?;
    let mut extra_buffer_permits = Vec::new();
    let mut batch_size = 1usize;

    for _ in 1..UDP_RELAY_RESPONSE_BATCH_LIMIT {
        match response_rx.try_recv() {
            Ok(response) => {
                batch_size += 1;
                extra_buffer_permits.push(
                    write_yamux_udp_relay_response(writer, response, username, bandwidth_monitor)
                        .await?,
                );
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        }
    }

    // `DatagramStreamIo` 的 write_all 只把一个 datagram 交给 SinkWriter；flush 才会
    // 推动底层 Yamux 子流实际写出。因此本批次最后统一 flush，减少每个回包一次 flush
    // 的开销，同时保留 datagram 边界。
    writer.flush().await?;
    if batch_size > 1 {
        debug!("Yamux UDP relay response 批量 flush：batch_size={batch_size}");
    }
    drop(first_buffer_permit);
    drop(extra_buffer_permits);
    Ok(())
}

async fn write_yamux_udp_relay_response<W>(
    writer: &mut W,
    response: QueuedUdpRelayResponse,
    username: Option<&str>,
    bandwidth_monitor: &BandwidthMonitor,
) -> Result<UdpRelayBufferedBytesPermit>
where
    W: AsyncWrite + Unpin,
{
    let QueuedUdpRelayResponse {
        packet,
        _buffer_permit: buffer_permit,
    } = response;
    // 这里不包 `ProxyResponse::Data`，因为 Yamux 子流本身已经代表当前 request。
    // 写入的是一帧完整的 UdpRelayPacket，DatagramStreamIo 会额外加长度前缀。
    let encoded = packet.encode().map_err(ProxyError::Protocol)?;
    if let Some(user) = username {
        bandwidth_monitor.record_sent(user, encoded.len() as u64);
    }
    writer.write_all(&encoded).await?;
    Ok(buffer_permit)
}

async fn send_yamux_connect_success<W>(
    writer: &mut W,
    request_id: String,
    message: &str,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let response = ConnectResponse {
        request_id,
        success: true,
        message: message.to_string(),
    };
    write_yamux_connect_response(writer, &response).await?;
    Ok(())
}

async fn send_yamux_connect_error<W>(
    writer: &mut W,
    request_id: String,
    message: String,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let response = ConnectResponse {
        request_id,
        success: false,
        message,
    };
    write_yamux_connect_response(writer, &response).await?;
    Ok(())
}
