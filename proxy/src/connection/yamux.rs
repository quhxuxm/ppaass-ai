use super::target::{relay_target_addr, target_addr_for_address};
use super::udp_relay_flow::{
    QueuedUdpRelayData, QueuedUdpRelayResponse, UdpRelayFlow, UdpRelayFlowChannels,
    UdpRelayFlowOptions, try_acquire_udp_relay_buffer, udp_relay_channel_size,
};
use super::*;
use std::collections::HashMap;

struct YamuxUdpRelayFlowContext {
    egress_state: Arc<EgressState>,
    channels: UdpRelayFlowChannels,
    connection_limiter: ConnectionLimiter,
    max_buffered_bytes: usize,
}

pub(super) async fn handle_yamux_tcp_stream(
    mut stream: StreamHandle,
    proxy_config: Arc<ProxyConfig>,
    egress_state: Arc<EgressState>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    username: Option<String>,
) -> Result<()> {
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
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    if idle_timeout_secs == 0 {
        match tokio::io::copy_bidirectional_with_sizes(
            &mut agent_stream,
            &mut target_stream,
            DEFAULT_STREAM_RELAY_BUFFER_SIZE,
            DEFAULT_STREAM_RELAY_BUFFER_SIZE,
        )
        .await
        {
            Ok((up, down)) => debug!("Yamux 子流中继已结束：上行 {}，下行 {}", up, down),
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
    let mut agent_buf = [0u8; DEFAULT_STREAM_RELAY_BUFFER_SIZE];
    let mut target_buf = [0u8; DEFAULT_STREAM_RELAY_BUFFER_SIZE];

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
        "Yamux 子流中继已结束：上行 {}，下行 {}",
        up_bytes, down_bytes
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
    let agent_io = DatagramStreamIo::new(agent_stream);
    let (mut reader, mut writer) = tokio::io::split(agent_io);
    let channel_size = udp_relay_channel_size(&proxy_config);
    let (response_tx, mut response_rx) =
        tokio::sync::mpsc::channel::<QueuedUdpRelayResponse>(channel_size);
    let (flow_done_tx, mut flow_done_rx) = tokio::sync::mpsc::channel::<u64>(channel_size);
    let flow_options = UdpRelayFlowOptions {
        idle_timeout: Duration::from_secs(proxy_config.udp_relay_idle_timeout_secs),
        channel_size,
    };
    let mut flows: HashMap<u64, UdpRelayFlow> = HashMap::new();
    let max_flows = proxy_config.max_udp_relay_flows_per_connection;
    let relay_idle_timeout = flow_options.idle_timeout;
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
                    bandwidth_monitor.record_received(user, n as u64);
                }

                let relay_packet = match UdpRelayPacket::decode(&request_buf[..n]) {
                    Ok(packet) => packet,
                    Err(e) => {
                        debug!("Yamux UDP relay 数据包解析失败：{e}");
                        continue;
                    }
                };

                if !flows.contains_key(&relay_packet.flow_id) {
                    if max_flows != 0 && flows.len() >= max_flows {
                        warn!(
                            "Yamux UDP relay flow 数已达上限（{}），丢弃 flow {} 的数据包",
                            max_flows, relay_packet.flow_id
                        );
                        continue;
                    }
                    let Some(flow_permit) = connection_limiter.try_acquire_udp_relay_flow() else {
                        warn!(
                            "proxy 全局 UDP relay flow 数已达上限（当前={}，上限={}），丢弃 flow {} 的数据包",
                            connection_limiter.active_udp_relay_flows(),
                            proxy_config.max_udp_relay_flows,
                            relay_packet.flow_id
                        );
                        continue;
                    };
                    let flow_context = YamuxUdpRelayFlowContext {
                        egress_state: egress_state.clone(),
                        channels: UdpRelayFlowChannels {
                            response_tx: response_tx.clone(),
                            flow_done_tx: flow_done_tx.clone(),
                        },
                        connection_limiter: connection_limiter.clone(),
                        max_buffered_bytes: proxy_config.max_udp_relay_buffered_bytes,
                    };
                    match spawn_yamux_udp_relay_flow(
                        relay_packet.flow_id,
                        relay_packet.address.clone(),
                        flow_permit,
                        flow_options,
                        flow_context,
                    ).await {
                        Ok(flow) => {
                            flows.insert(relay_packet.flow_id, flow);
                        }
                        Err(e) => {
                            debug!(
                                "Yamux UDP relay flow {} 连接目标失败：{}",
                                relay_packet.flow_id, e
                            );
                            continue;
                        }
                    }
                }

                let flow_id = relay_packet.flow_id;
                if let Some(flow) = flows.get(&flow_id) {
                    let Some(buffer_permit) = try_acquire_udp_relay_buffer(
                        &connection_limiter,
                        proxy_config.max_udp_relay_buffered_bytes,
                        flow_id,
                        relay_packet.data.len(),
                        "上行",
                    ) else {
                        continue;
                    };
                    let queued = QueuedUdpRelayData {
                        data: relay_packet.data,
                        _buffer_permit: buffer_permit,
                    };
                    match flow.tx.try_send(queued) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            debug!("Yamux UDP relay flow {flow_id} 发送队列已满，丢弃一个 UDP 数据包");
                        }
                        Err(TrySendError::Closed(_)) => {
                            flows.remove(&flow_id);
                        }
                    }
                }
            }
            response = response_rx.recv() => {
                let Some(response) = response else { break };
                let encoded = response
                    .packet
                    .encode()
                    .map_err(ProxyError::Protocol)?;
                if let Some(user) = &username {
                    bandwidth_monitor.record_sent(user, encoded.len() as u64);
                }
                match tokio::time::timeout(relay_idle_timeout, async {
                    writer.write_all(&encoded).await?;
                    writer.flush().await
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
                flows.remove(&flow_id);
            }
        }
    }

    debug!("Yamux UDP 共享中继已结束");
    Ok(())
}

async fn spawn_yamux_udp_relay_flow(
    flow_id: u64,
    address: Address,
    flow_permit: UdpRelayFlowPermit,
    options: UdpRelayFlowOptions,
    context: YamuxUdpRelayFlowContext,
) -> Result<UdpRelayFlow> {
    let YamuxUdpRelayFlowContext {
        egress_state,
        channels,
        connection_limiter,
        max_buffered_bytes,
    } = context;
    let target_addr = relay_target_addr(&address)?;
    let socket = egress_state.connect_udp(&target_addr).await.map_err(|e| {
        ProxyError::Connection(format!("Failed to connect Yamux UDP relay target: {e}"))
    })?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<QueuedUdpRelayData>(options.channel_size);
    let response_address = address.clone();
    let response_tx = channels.response_tx;
    let flow_done_tx = channels.flow_done_tx;
    let flow_idle_timeout = options.idle_timeout;

    spawn_guarded("proxy yamux udp relay flow", async move {
        let _flow_permit = flow_permit;
        let mut buf = vec![0u8; 65535];
        let idle = tokio::time::sleep(flow_idle_timeout);
        tokio::pin!(idle);

        loop {
            tokio::select! {
                _ = &mut idle => break,
                maybe_data = rx.recv() => {
                    let Some(queued) = maybe_data else { break };
                    let data = queued.data;
                    match tokio::time::timeout(flow_idle_timeout, socket.send(&data)).await {
                        Ok(Ok(_)) => {
                            idle.as_mut().reset(tokio::time::Instant::now() + flow_idle_timeout);
                        }
                        Ok(Err(e)) => {
                            debug!("Yamux UDP relay flow {flow_id} 发送失败：{e}");
                            break;
                        }
                        Err(_) => {
                            debug!(
                                "Yamux UDP relay flow {flow_id} 发送超过 {} 秒，关闭该 flow",
                                flow_idle_timeout.as_secs()
                            );
                            break;
                        }
                    }
                }
                read = socket.recv(&mut buf) => {
                    match read {
                        Ok(n) => {
                            let Some(buffer_permit) = try_acquire_udp_relay_buffer(
                                &connection_limiter,
                                max_buffered_bytes,
                                flow_id,
                                n,
                                "下行",
                            ) else {
                                debug!("Yamux UDP relay flow {flow_id} 响应缓冲预算不足，关闭该 flow 以释放 socket");
                                break;
                            };
                            let response = QueuedUdpRelayResponse {
                                packet: UdpRelayPacket {
                                    flow_id,
                                    address: response_address.clone(),
                                    data: buf[..n].to_vec(),
                                },
                                _buffer_permit: buffer_permit,
                            };
                            match response_tx.try_send(response) {
                                Ok(()) => {
                                    idle.as_mut().reset(tokio::time::Instant::now() + flow_idle_timeout);
                                }
                                Err(TrySendError::Full(_)) => {
                                    debug!("Yamux UDP relay flow {flow_id} 响应队列已满，关闭该 flow 以释放 socket");
                                    break;
                                }
                                Err(TrySendError::Closed(_)) => break,
                            }
                        }
                        Err(e) => {
                            debug!("Yamux UDP relay flow {flow_id} 接收失败：{e}");
                            break;
                        }
                    }
                }
            }
        }
        drop(socket);
        let _ = flow_done_tx.send(flow_id).await;
        debug!("Yamux UDP relay flow {flow_id} 已结束");
    });

    Ok(UdpRelayFlow { tx })
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
