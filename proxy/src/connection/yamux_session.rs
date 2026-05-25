use super::*;

impl ServerConnection {
    pub(super) async fn handle_tcp_yamux_connect(&mut self, stream_id: String) -> Result<()> {
        debug!("正在建立 TCP Yamux 会话：stream_id={stream_id}");

        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();
        let stream_id_filter = stream_id.clone();

        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        let stream = (&mut self.reader)
            .take_while(move |res| {
                let continue_stream = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        !(packet.stream_id == stream_id_stop
                            && packet.is_end
                            && packet.data.is_empty())
                    }
                    Ok(_) => true,
                    Err(_) => false,
                };
                futures::future::ready(continue_stream)
            })
            .filter_map(move |res| {
                let user = username_stream.as_ref();
                let monitor = &monitor_stream;

                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
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
        let agent_io = AgentIo { reader, writer };
        let mut session = Session::new_server(
            agent_io,
            self.proxy_config.yamux.tcp_settings().to_tokio_config(),
        );
        let proxy_config = self.proxy_config.clone();
        let egress_state = self.egress_state.clone();
        let bandwidth_monitor = self.bandwidth_monitor.clone();
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let mut stream_tasks = Vec::new();

        while let Some(result) = session.next().await {
            match result {
                Ok(stream) => {
                    prune_finished_yamux_stream_tasks(&mut stream_tasks);
                    let proxy_config = proxy_config.clone();
                    let egress_state = egress_state.clone();
                    let bandwidth_monitor = bandwidth_monitor.clone();
                    let username = username.clone();
                    let task = spawn_guarded("proxy yamux tcp stream", async move {
                        if let Err(err) = handle_yamux_tcp_stream(
                            stream,
                            proxy_config,
                            egress_state,
                            bandwidth_monitor,
                            username,
                        )
                        .await
                        {
                            debug!("Yamux TCP 子流已结束：{err}");
                        }
                    });
                    stream_tasks.push(task);
                }
                Err(err) => {
                    debug!("TCP Yamux 会话结束 stream_id={stream_id}: {err}");
                    break;
                }
            }
        }

        abort_yamux_stream_tasks("TCP", &stream_id, stream_tasks).await;
        Ok(())
    }

    pub(super) async fn handle_udp_yamux_connect(&mut self, stream_id: String) -> Result<()> {
        debug!("正在建立 UDP Yamux 会话：stream_id={stream_id}");

        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();
        let stream_id_filter = stream_id.clone();

        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        let stream = (&mut self.reader)
            .take_while(move |res| {
                let continue_stream = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        !(packet.stream_id == stream_id_stop
                            && packet.is_end
                            && packet.data.is_empty())
                    }
                    Ok(_) => true,
                    Err(_) => false,
                };
                futures::future::ready(continue_stream)
            })
            .filter_map(move |res| {
                let user = username_stream.as_ref();
                let monitor = &monitor_stream;

                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
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
        let agent_io = AgentIo { reader, writer };
        let mut session = Session::new_server(
            agent_io,
            self.proxy_config.yamux.udp_settings().to_tokio_config(),
        );
        let proxy_config = self.proxy_config.clone();
        let egress_state = self.egress_state.clone();
        let bandwidth_monitor = self.bandwidth_monitor.clone();
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let connection_limiter = self.connection_limiter.clone();
        let mut stream_tasks = Vec::new();

        while let Some(result) = session.next().await {
            match result {
                Ok(stream) => {
                    prune_finished_yamux_stream_tasks(&mut stream_tasks);
                    let proxy_config = proxy_config.clone();
                    let egress_state = egress_state.clone();
                    let bandwidth_monitor = bandwidth_monitor.clone();
                    let username = username.clone();
                    let connection_limiter = connection_limiter.clone();
                    let task = spawn_guarded("proxy yamux udp stream", async move {
                        if let Err(err) = handle_yamux_udp_stream(
                            stream,
                            proxy_config,
                            egress_state,
                            bandwidth_monitor,
                            username,
                            connection_limiter,
                        )
                        .await
                        {
                            debug!("Yamux UDP 子流已结束：{err}");
                        }
                    });
                    stream_tasks.push(task);
                }
                Err(err) => {
                    debug!("UDP Yamux 会话结束 stream_id={stream_id}: {err}");
                    break;
                }
            }
        }

        abort_yamux_stream_tasks("UDP", &stream_id, stream_tasks).await;
        Ok(())
    }
}

fn prune_finished_yamux_stream_tasks(tasks: &mut Vec<tokio::task::JoinHandle<()>>) {
    tasks.retain(|task| !task.is_finished());
}

async fn abort_yamux_stream_tasks(
    transport: &str,
    stream_id: &str,
    tasks: Vec<tokio::task::JoinHandle<()>>,
) {
    if tasks.is_empty() {
        return;
    }

    let task_count = tasks.len();
    debug!(
        "{transport} Yamux 会话结束 stream_id={stream_id}，正在关闭 {task_count} 个未完成子流任务"
    );

    for task in &tasks {
        task.abort();
    }

    for task in tasks {
        match task.await {
            Ok(()) => {}
            Err(err) if err.is_cancelled() => {}
            Err(err) => {
                debug!("{transport} Yamux 子流任务回收时返回错误 stream_id={stream_id}: {err}")
            }
        }
    }
}
