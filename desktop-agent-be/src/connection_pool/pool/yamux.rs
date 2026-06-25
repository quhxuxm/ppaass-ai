//! Yamux 连接池。
//!
//! 每个 `YamuxClientConnection` 是一条 raw TCP 上的外层 Yamux session。真实目标
//! 连接通过在 session 内打开子流，并在子流内执行 PPAASS 加密协议完成。

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
            // 简单轮询选择 session，避免所有新子流压到同一条外层连接。
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
                    return Ok(ConnectedStream::new_yamux(stream, request_id));
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

        // 同一时间只允许一个补充任务创建 session，避免并发请求把 session 数打爆。
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
            let transport = self.yamux_transport;
            let session_id = self.yamux_next_session_id.fetch_add(1, Ordering::AcqRel);
            set.spawn(async move {
                let _permit = semaphore.acquire().await.ok();
                new_yamux_connection(&config, bind_ip, bind_interface, transport)
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
            TransportProtocol::Udp => self.config.yamux.udp_session_count(),
            TransportProtocol::Tcp => self.config.yamux.tcp_session_count(),
        }
    }
}
