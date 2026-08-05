use super::*;

impl ServerConnection {
    #[instrument(skip(self, udp_socket))]
    pub(in crate::connection) async fn relay_udp(
        &mut self,
        stream_id: String,
        udp_socket: UdpSocket,
    ) -> Result<()> {
        // UDP 没有天然字节流，这里用 StreamReader/SinkWriter 拼成类流式中继。
        // 这个 legacy UDP 路径面向单个已 connect 的 UDP socket；
        // 多目标 UDP 共享连接走 udp_relay.rs 的 flow_id 机制。
        let stream_id_filter = stream_id.clone();
        let authorization = self.authorization_context()?;
        let authorization_guard = authorization.enforce(
            PERMISSION_PROXY_CONNECT_UDP,
            self.authorization_recheck_secs(),
        );
        tokio::pin!(authorization_guard);

        // 使用自定义 Sink 将 UDP 响应数据重新封装成 proxy DataPacket。
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        // 从 agent 到 UDP 的方向只消费当前 stream_id 的数据包。
        // 遇到同一 stream 的空 end 包时停止，让对端主动关闭能传播到本地中继。
        let stream = (&mut self.reader)
            .take_while(move |res| {
                let continue_stream = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        !(packet.stream_id == stream_id_stop
                            && packet.is_end
                            && packet.data.is_empty())
                    }
                    Ok(_) => true,
                    // 出错时停止流，防止连接泄漏
                    Err(_) => false,
                };
                futures::future::ready(continue_stream)
            })
            .filter_map(move |res| {
                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        // 只处理该流的数据包
                        trace!(
                            packet.stream_id,
                            stream_id_filter, "从 agent 收到 UDP 数据包：{packet:?}"
                        );
                        if packet.stream_id == stream_id_filter && !packet.data.is_empty() {
                            Some(Ok(Bytes::from(packet.data)))
                        } else {
                            None
                        }
                    }
                    Ok(_) => None,
                    Err(e) => Some(Err(io::Error::other(e))),
                };

                futures::future::ready(result)
            });

        let writer = SinkWriter::new(sink);
        let reader = StreamReader::new(stream);

        // AgentIo 把“从 agent 读”和“写回 agent”合成一个双向 IO。
        let agent_io = AgentIo { reader, writer };

        let udp_socket = Arc::new(udp_socket);
        let udp_recv = udp_socket.clone();
        let udp_send = udp_socket.clone();

        let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);

        let udp_relay_idle_timeout =
            Duration::from_secs(self.proxy_config.udp_relay_idle_timeout_secs);
        let idle_timeout = tokio::time::sleep(udp_relay_idle_timeout);
        tokio::pin!(idle_timeout);
        let mut agent_buf = vec![0u8; 65535];
        let mut udp_buf = vec![0u8; 65535];

        loop {
            // 任一方向有数据就重置 idle；两边都长期无数据才关闭 UDP socket。
            tokio::select! {
                biased;
                authorization_result = &mut authorization_guard => {
                    warn!("legacy UDP relay 授权已失效，主动关闭：{:?}", authorization_result.as_ref().err());
                    return authorization_result;
                }
                _ = &mut idle_timeout => {
                    debug!(
                        "UDP 中继空闲超过 {} 秒，关闭 socket",
                        udp_relay_idle_timeout.as_secs()
                    );
                    break;
                }
                read = agent_reader.read(&mut agent_buf) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = &agent_buf[..n];
                            trace!(
                                "从 agent 收到发往目标的 UDP 数据：{:?}\n{}",
                                udp_socket.peer_addr(),
                                pretty_hex::pretty_hex(&data)
                            );
                            let send = tokio::time::timeout(
                                udp_relay_idle_timeout,
                                udp_send.send(data),
                            );
                            let send_result = tokio::select! {
                                biased;
                                authorization_result = &mut authorization_guard => {
                                    warn!("legacy UDP relay 授权已失效，主动关闭：{:?}", authorization_result.as_ref().err());
                                    return authorization_result;
                                }
                                send_result = send => send_result,
                            };
                            match send_result {
                                Ok(Ok(_)) => {
                                    idle_timeout.as_mut().reset(tokio::time::Instant::now() + udp_relay_idle_timeout);
                                }
                                Ok(Err(e)) => {
                                    debug!("UDP 发送错误：{}", e);
                                    break;
                                }
                                Err(_) => {
                                    debug!("UDP 发送超过 {} 秒，关闭 socket", udp_relay_idle_timeout.as_secs());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("读取 agent 数据错误：{}", e);
                            break;
                        }
                    }
                }
                recv = udp_recv.recv(&mut udp_buf) => {
                    match recv {
                        Ok(n) => {
                            let data = &udp_buf[..n];
                            trace!(
                                "从目标收到发往 agent 的 UDP 数据：{:?}\n{}",
                                udp_socket.peer_addr(),
                                pretty_hex::pretty_hex(&data)
                            );
                            let write = tokio::time::timeout(udp_relay_idle_timeout, async {
                                agent_writer.write_all(data).await?;
                                agent_writer.flush().await
                            });
                            let write_result = tokio::select! {
                                biased;
                                authorization_result = &mut authorization_guard => {
                                    warn!("legacy UDP relay 授权已失效，主动关闭：{:?}", authorization_result.as_ref().err());
                                    return authorization_result;
                                }
                                write_result = write => write_result,
                            };
                            match write_result {
                                Ok(Ok(())) => {
                                    idle_timeout.as_mut().reset(tokio::time::Instant::now() + udp_relay_idle_timeout);
                                }
                                Ok(Err(e)) => {
                                    debug!("写入 agent 数据错误：{}", e);
                                    break;
                                }
                                Err(_) => {
                                    debug!("写入 agent 超过 {} 秒，关闭 UDP 中继", udp_relay_idle_timeout.as_secs());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("UDP 接收错误：{}", e);
                            break;
                        }
                    }
                }
            }
        }

        debug!("UDP 中继已结束");
        Ok(())
    }

    pub(in crate::connection) async fn relay<S>(
        &mut self,
        stream_id: String,
        target_stream: &mut S,
        transport: TransportProtocol,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        // TCP 中继把 agent 数据包流和目标 TCP 流转换成双向字节拷贝。
        // legacy 模式下，一条 agent->proxy TCP 连接通常只服务一个 request_id。
        let stream_id_filter = stream_id.clone();
        let permission = match transport {
            TransportProtocol::Tcp => PERMISSION_PROXY_CONNECT_TCP,
            TransportProtocol::Udp => PERMISSION_PROXY_CONNECT_UDP,
        };
        let authorization = self.authorization_context()?;
        let authorization_guard =
            authorization.enforce(permission, self.authorization_recheck_secs());
        tokio::pin!(authorization_guard);

        // 使用自定义 Sink 实现，避免 SinkExt::with 与闭包引发 HRTB 问题
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        // agent 数据流中可能混有其他消息，只取当前 stream 的 DataPacket。
        // 这种过滤让同一 reader 的非 Data/其他 stream_id 消息不会污染当前目标连接。
        let stream = (&mut self.reader)
            .take_while(move |res| {
                let continue_stream = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        !(packet.stream_id == stream_id_stop
                            && packet.is_end
                            && packet.data.is_empty())
                    }
                    Ok(_) => true,
                    // 出错时停止流，防止连接泄漏
                    Err(_) => false,
                };
                futures::future::ready(continue_stream)
            })
            .filter_map(move |res| {
                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        // 只处理该流的数据包
                        if packet.stream_id == stream_id_filter {
                            if !packet.data.is_empty() {
                                Some(Ok(Bytes::from(packet.data)))
                            } else {
                                None
                            }
                        } else {
                            // 其他流的数据，跳过
                            None
                        }
                    }
                    Ok(_) => None, // 忽略非 Data 数据包
                    Err(e) => Some(Err(io::Error::other(e))),
                };

                futures::future::ready(result)
            });

        let writer = SinkWriter::new(sink);
        let reader = StreamReader::new(stream);

        // AgentIo 让 packet-based 的 agent 连接呈现为 AsyncRead/AsyncWrite。
        let mut agent_io = AgentIo { reader, writer };

        let tcp_relay_idle_timeout_secs = self.proxy_config.tcp_relay_idle_timeout_secs;
        let half_close_idle_timeout_secs = self.proxy_config.tcp_relay_half_close_idle_timeout_secs;
        let timeouts =
            TcpRelayTimeouts::new(tcp_relay_idle_timeout_secs, half_close_idle_timeout_secs);

        let relay = relay_tcp_with_half_close(target_stream, &mut agent_io, timeouts);
        tokio::pin!(relay);
        let (up_bytes, down_bytes) = tokio::select! {
            biased;
            authorization_result = &mut authorization_guard => {
                warn!(
                    ?transport,
                    "active relay 授权已失效，主动关闭：{:?}",
                    authorization_result.as_ref().err()
                );
                return authorization_result;
            }
            relay_result = &mut relay => relay_result?,
        };

        debug!("中继已结束：上行 {}，下行 {}", up_bytes, down_bytes);

        Ok(())
    }
}
