use super::target::relay_target_addr;
use super::udp_relay_flow::{
    QueuedUdpRelayData, QueuedUdpRelayResponse, UdpRelayFlow, UdpRelayFlowChannels,
    UdpRelayFlowOptions, try_acquire_udp_relay_buffer, udp_relay_channel_size,
};
use super::*;
use std::collections::HashMap;

impl ServerConnection {
    pub(super) async fn handle_udp_relay_connect(
        &mut self,
        connect_request: ConnectRequest,
    ) -> Result<()> {
        debug!("正在建立 UDP 共享中继");
        self.send_connect_success(connect_request.request_id.clone(), "UDP relay connected")
            .await?;

        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let channel_size = udp_relay_channel_size(&self.proxy_config);
        let (response_tx, mut response_rx) =
            tokio::sync::mpsc::channel::<QueuedUdpRelayResponse>(channel_size);
        let (flow_done_tx, mut flow_done_rx) = tokio::sync::mpsc::channel::<u64>(channel_size);
        let flow_options = UdpRelayFlowOptions {
            idle_timeout: Duration::from_secs(self.proxy_config.udp_relay_idle_timeout_secs),
            channel_size,
        };
        let mut flows: HashMap<u64, UdpRelayFlow> = HashMap::new();
        let max_flows = self.proxy_config.max_udp_relay_flows_per_connection;
        let stream_id = connect_request.request_id;
        let relay_idle_timeout = flow_options.idle_timeout;
        let relay_idle = tokio::time::sleep(relay_idle_timeout);
        tokio::pin!(relay_idle);

        loop {
            tokio::select! {
                _ = &mut relay_idle => {
                    debug!(
                        "UDP 共享中继空闲超过 {} 秒，关闭该连接",
                        relay_idle_timeout.as_secs()
                    );
                    break;
                }
                request = self.reader.next() => {
                    let request = match request {
                        Some(Ok(request)) => request,
                        Some(Err(e)) => return Err(ProxyError::Protocol(protocol::ProtocolError::Io(e))),
                        None => break,
                    };

                    let ProxyRequest::Data(packet) = request else {
                        continue;
                    };
                    if packet.stream_id != stream_id {
                        continue;
                    }
                    if packet.is_end && packet.data.is_empty() {
                        break;
                    }
                    if packet.data.is_empty() {
                        continue;
                    }

                    relay_idle.as_mut().reset(tokio::time::Instant::now() + relay_idle_timeout);

                    if let Some(user) = &username {
                        self.bandwidth_monitor.record_received(user, packet.data.len() as u64);
                    }

                    let relay_packet = match UdpRelayPacket::decode(&packet.data) {
                        Ok(packet) => packet,
                        Err(e) => {
                            debug!("UDP relay 数据包解析失败：{e}");
                            continue;
                        }
                    };

                    if !flows.contains_key(&relay_packet.flow_id) {
                        if max_flows != 0 && flows.len() >= max_flows {
                            warn!(
                                "UDP relay flow 数已达上限（{}），丢弃 flow {} 的数据包",
                                max_flows, relay_packet.flow_id
                            );
                            continue;
                        }
                        let Some(flow_permit) = self.connection_limiter.try_acquire_udp_relay_flow() else {
                            warn!(
                                "proxy 全局 UDP relay flow 数已达上限（当前={}，上限={}），丢弃 flow {} 的数据包",
                                self.connection_limiter.active_udp_relay_flows(),
                                self.proxy_config.max_udp_relay_flows,
                                relay_packet.flow_id
                            );
                            continue;
                        };
                        match self.spawn_udp_relay_flow(
                            relay_packet.flow_id,
                            relay_packet.address.clone(),
                            UdpRelayFlowChannels {
                                response_tx: response_tx.clone(),
                                flow_done_tx: flow_done_tx.clone(),
                            },
                            flow_permit,
                            flow_options,
                        ).await {
                            Ok(flow) => {
                                flows.insert(relay_packet.flow_id, flow);
                            }
                            Err(e) => {
                                debug!(
                                    "UDP relay flow {} 连接目标失败：{}",
                                    relay_packet.flow_id, e
                                );
                                continue;
                            }
                        }
                    }

                    let flow_id = relay_packet.flow_id;
                    if let Some(flow) = flows.get(&flow_id) {
                        let Some(buffer_permit) = try_acquire_udp_relay_buffer(
                            &self.connection_limiter,
                            self.proxy_config.max_udp_relay_buffered_bytes,
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
                                debug!("UDP relay flow {flow_id} 发送队列已满，丢弃一个 UDP 数据包");
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
                        self.bandwidth_monitor.record_sent(user, encoded.len() as u64);
                    }
                    let packet = protocol::DataPacket {
                        stream_id: stream_id.clone(),
                        data: encoded,
                        is_end: false,
                    };
                    self.writer
                        .send(ProxyResponse::Data(packet))
                        .await
                        .map_err(|e| ProxyError::Connection(format!("Failed to send UDP relay response: {e}")))?;
                    relay_idle.as_mut().reset(tokio::time::Instant::now() + relay_idle_timeout);
                }
                done = flow_done_rx.recv() => {
                    let Some(flow_id) = done else { break };
                    flows.remove(&flow_id);
                }
            }
        }

        debug!("UDP 共享中继已结束");
        Ok(())
    }

    async fn spawn_udp_relay_flow(
        &self,
        flow_id: u64,
        address: Address,
        channels: UdpRelayFlowChannels,
        flow_permit: UdpRelayFlowPermit,
        options: UdpRelayFlowOptions,
    ) -> Result<UdpRelayFlow> {
        let target_addr = relay_target_addr(&address)?;
        let socket = self
            .egress_state
            .connect_udp(&target_addr)
            .await
            .map_err(|e| {
                ProxyError::Connection(format!("Failed to connect UDP relay target: {e}"))
            })?;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<QueuedUdpRelayData>(options.channel_size);
        let response_address = address.clone();
        let connection_limiter = self.connection_limiter.clone();
        let max_buffered_bytes = self.proxy_config.max_udp_relay_buffered_bytes;
        let response_tx = channels.response_tx;
        let flow_done_tx = channels.flow_done_tx;
        let flow_idle_timeout = options.idle_timeout;

        spawn_guarded("proxy udp relay flow", async move {
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
                                debug!("UDP relay flow {flow_id} 发送失败：{e}");
                                break;
                            }
                            Err(_) => {
                                debug!(
                                    "UDP relay flow {flow_id} 发送超过 {} 秒，关闭该 flow",
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
                                    debug!("UDP relay flow {flow_id} 响应缓冲预算不足，关闭该 flow 以释放 socket");
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
                                        debug!("UDP relay flow {flow_id} 响应队列已满，关闭该 flow 以释放 socket");
                                        break;
                                    }
                                    Err(TrySendError::Closed(_)) => break,
                                }
                            }
                            Err(e) => {
                                debug!("UDP relay flow {flow_id} 接收失败：{e}");
                                break;
                            }
                        }
                    }
                }
            }
            drop(socket);
            let _ = flow_done_tx.send(flow_id).await;
            debug!("UDP relay flow {flow_id} 已结束");
        });

        Ok(UdpRelayFlow { tx })
    }
}
