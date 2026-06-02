use super::*;

impl ConnectionPool {
    pub(super) async fn get_yamux_connected_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<ConnectedStream> {
        let target_size = self.yamux_target_size();
        let mut attempts = 0usize;

        loop {
            self.ensure_yamux_sessions(target_size).await?;
            let session = self
                .next_yamux_session()
                .await
                .ok_or_else(|| AgentError::Connection("没有可用的 Yamux 代理连接".to_string()))?;

            match session
                .connection
                .connect_to_target(address.clone(), transport)
                .await
            {
                Ok((stream, request_id)) => {
                    debug!("已通过 Yamux 子流连接目标：{:?}", address);
                    return if transport == TransportProtocol::Udp {
                        Ok(ConnectedStream::new_yamux_datagram(stream, request_id))
                    } else {
                        Ok(ConnectedStream::new_yamux(stream, request_id))
                    };
                }
                Err(err) => {
                    let message = err.to_string();
                    if is_yamux_target_connect_error(&message) {
                        return Err(AgentError::Connection(message));
                    }

                    warn!(
                        "Yamux 代理连接不可用，移除 session={} 并重试：{}",
                        session.id, message
                    );
                    self.remove_yamux_session(session.id).await;
                    attempts += 1;
                    if attempts >= target_size.max(3) {
                        return Err(AgentError::Connection(message));
                    }
                }
            }
        }
    }

    pub(super) async fn ensure_yamux_sessions(&self, target_size: usize) -> Result<usize> {
        if target_size == 0 {
            return Ok(0);
        }

        if self.yamux_sessions.lock().await.len() >= target_size {
            return Ok(0);
        }

        let _guard = self.yamux_refill_lock.lock().await;
        let current_size = self.yamux_sessions.lock().await.len();
        if current_size >= target_size {
            return Ok(0);
        }

        let to_create = target_size - current_size;
        debug!(
            "正在补充 {} Yamux 连接池：创建 {} 条连接（当前：{}）",
            self.pool_name, to_create, current_size
        );

        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_POOL_CONNECTS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..to_create {
            let config = self.config.clone();
            let semaphore = semaphore.clone();
            let bind_ip = self.get_proxy_bind_ip();
            let bind_interface = self.get_proxy_bind_interface();
            let outer_address = self
                .yamux_outer_address
                .clone()
                .ok_or_else(|| AgentError::Connection("Yamux outer address missing".to_string()))?;
            let transport = self
                .yamux_transport
                .ok_or_else(|| AgentError::Connection("Yamux transport missing".to_string()))?;
            let session_id = self.yamux_next_session_id.fetch_add(1, Ordering::AcqRel);
            set.spawn(async move {
                let _permit = semaphore.acquire().await.ok();
                ProxyConnection::new_yamux_connection(
                    &config,
                    bind_ip,
                    bind_interface,
                    outer_address,
                    transport,
                )
                .await
                .map(|connection| YamuxSessionHandle {
                    id: session_id,
                    connection,
                })
            });
        }

        let mut success_count = 0usize;
        let mut failure_count = 0usize;
        let mut last_error = None;
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(session)) => {
                    let mut sessions = self.yamux_sessions.lock().await;
                    if sessions.len() >= target_size {
                        set.abort_all();
                        break;
                    }
                    sessions.push(session);
                    success_count += 1;
                }
                Ok(Err(e)) => {
                    debug!("{} Yamux 代理连接创建失败：{}", self.pool_name, e);
                    failure_count += 1;
                    last_error = Some(e);
                }
                Err(e) if e.is_cancelled() => {}
                Err(e) => warn!("Yamux 补充任务 join 错误：{}", e),
            }
        }

        if success_count == 0 && self.yamux_sessions.lock().await.is_empty() {
            let err = last_error
                .unwrap_or_else(|| AgentError::Connection("创建 Yamux 代理连接失败".to_string()));
            warn!("{} Yamux 连接池补充失败：{}", self.pool_name, err);
            return Err(err);
        }

        if failure_count > 0 {
            debug!(
                "{} Yamux 连接池补充部分失败：成功 {} 条，失败 {} 条",
                self.pool_name, success_count, failure_count
            );
        }

        Ok(success_count)
    }

    async fn next_yamux_session(&self) -> Option<YamuxSessionHandle> {
        let sessions = self.yamux_sessions.lock().await;
        if sessions.is_empty() {
            return None;
        }

        let index = self.yamux_next_index.fetch_add(1, Ordering::AcqRel) % sessions.len();
        Some(sessions[index].clone())
    }

    async fn remove_yamux_session(&self, session_id: usize) {
        let mut sessions = self.yamux_sessions.lock().await;
        sessions.retain(|session| session.id != session_id);
    }

    pub(super) fn yamux_target_size(&self) -> usize {
        match self.yamux_transport {
            Some(TransportProtocol::Udp) => self.config.yamux.udp_session_count(),
            _ => self.config.yamux.tcp_session_count(),
        }
    }
}
