use super::*;

impl ServerConnection {
    #[instrument(skip(self, udp_socket))]
    pub(super) async fn relay_udp(
        &mut self,
        stream_id: String,
        udp_socket: UdpSocket,
    ) -> Result<()> {
        // UDP 没有天然字节流，这里用 StreamReader/SinkWriter 拼成类流式中继。
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();
        let stream_id_filter = stream_id.clone();

        // 使用自定义 Sink 将 UDP 响应数据重新封装成 proxy DataPacket。
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        // 从 agent 到 UDP 的方向只消费当前 stream_id 的数据包。
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
                let user = username_stream.as_ref();
                let monitor = &monitor_stream;

                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        // 只处理该流的数据包
                        trace!(
                            packet.stream_id,
                            stream_id_filter, "从 agent 收到 UDP 数据包：{packet:?}"
                        );
                        if packet.stream_id == stream_id_filter && !packet.data.is_empty() {
                            if let Some(u) = user {
                                monitor.record_received(u, packet.data.len() as u64);
                            }
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
        let mut agent_buf = [0u8; 65535];
        let mut udp_buf = [0u8; 65535];

        loop {
            tokio::select! {
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
                            match tokio::time::timeout(udp_relay_idle_timeout, udp_send.send(data)).await {
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
                            let write_result = tokio::time::timeout(udp_relay_idle_timeout, async {
                                agent_writer.write_all(data).await?;
                                agent_writer.flush().await
                            }).await;
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

    pub(super) async fn relay<S>(&mut self, stream_id: String, target_stream: &mut S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        // TCP 中继把 agent 数据包流和目标 TCP 流转换成双向字节拷贝。
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();
        let stream_id_filter = stream_id.clone();

        // 使用自定义 Sink 实现，避免 SinkExt::with 与闭包引发 HRTB 问题
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        // agent 数据流中可能混有其他消息，只取当前 stream 的 DataPacket。
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
                let user = username_stream.as_ref();
                let monitor = &monitor_stream;

                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        // 只处理该流的数据包
                        if packet.stream_id == stream_id_filter {
                            if !packet.data.is_empty() {
                                if let Some(u) = user {
                                    monitor.record_received(u, packet.data.len() as u64);
                                }
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
        let agent_io = AgentIo { reader, writer };

        let tcp_relay_idle_timeout_secs = self.proxy_config.tcp_relay_idle_timeout_secs;
        if tcp_relay_idle_timeout_secs == 0 {
            // 兼容旧行为：不配置超时时按任一端关闭来结束中继。
            let mut agent_io = agent_io;
            match tokio::io::copy_bidirectional_with_sizes(
                target_stream,
                &mut agent_io,
                DEFAULT_STREAM_RELAY_BUFFER_SIZE,
                DEFAULT_STREAM_RELAY_BUFFER_SIZE,
            )
            .await
            {
                Ok((up, down)) => debug!("中继已结束：上行 {}，下行 {}", up, down),
                Err(e) => debug!("中继错误：{}", e),
            }
            return Ok(());
        }

        let idle_timeout = Duration::from_secs(tcp_relay_idle_timeout_secs);
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);

        let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);
        let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);
        let mut up_bytes: u64 = 0;
        let mut down_bytes: u64 = 0;
        let mut agent_buf = [0u8; DEFAULT_STREAM_RELAY_BUFFER_SIZE];
        let mut target_buf = [0u8; DEFAULT_STREAM_RELAY_BUFFER_SIZE];

        loop {
            tokio::select! {
                _ = &mut idle => {
                    debug!(
                        "TCP 中继空闲超过 {} 秒，关闭连接",
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
                                    debug!("TCP relay 写入目标失败：{}", e);
                                    break;
                                }
                                Err(_) => {
                                    debug!("TCP relay 写入目标超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("TCP relay 读取 agent 数据失败：{}", e);
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
                                    debug!("TCP relay 写回 agent 失败：{}", e);
                                    break;
                                }
                                Err(_) => {
                                    debug!("TCP relay 写回 agent 超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("TCP relay 读取目标数据失败：{}", e);
                            break;
                        }
                    }
                }
            }
        }

        debug!("中继已结束：上行 {}，下行 {}", up_bytes, down_bytes);

        Ok(())
    }
}
