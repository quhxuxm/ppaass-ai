//! Yamux session 管理。
//!
//! 每个 `YamuxClientConnection` 是一条 raw TCP 上的外层 Yamux session。真实目标
//! 连接通过在 session 内打开子流，并在子流内执行 PPAASS 加密协议完成。

use super::*;

impl YamuxSessionManager {
    pub(super) async fn open_target_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<YamuxTargetStream> {
        let max_sessions = self.yamux_target_size();
        let mut attempts = 0usize;

        loop {
            self.prune_closed_yamux_sessions().await;
            self.ensure_yamux_sessions(1.min(max_sessions)).await?;

            let session = match self.next_yamux_session_with_capacity().await {
                Some(session) => session,
                None => {
                    if self.ensure_additional_yamux_session(max_sessions).await? > 0 {
                        continue;
                    }
                    self.next_yamux_session().await.ok_or_else(|| {
                        AgentError::Connection("没有可用的 Yamux 代理连接".to_string())
                    })?
                }
            };

            let connect = if session.connection.has_immediate_stream_capacity() {
                session
                    .connection
                    .try_connect_to_target(address.clone(), transport)
                    .await
            } else {
                session
                    .connection
                    .connect_to_target(address.clone(), transport)
                    .await
            };

            match connect {
                Ok((stream, request_id)) => {
                    debug!("已通过 Yamux 子流连接目标：{:?}", address);
                    return Ok(YamuxTargetStream::new_yamux(stream, request_id));
                }
                Err(err) => {
                    let message = err.to_string();
                    if is_yamux_session_capacity_error(&message) {
                        if self.ensure_additional_yamux_session(max_sessions).await? > 0 {
                            continue;
                        }
                        attempts += 1;
                        if attempts >= max_sessions.max(3) {
                            return Err(AgentError::Connection(message));
                        }
                        tokio::task::yield_now().await;
                        continue;
                    }

                    if is_yamux_target_connect_error(&message) {
                        return Err(AgentError::Connection(message));
                    }

                    warn!(
                        "Yamux 代理连接不可用，移除 session={} 并重试：{}",
                        session.id, message
                    );
                    self.remove_yamux_session(session.id).await;
                    attempts += 1;
                    if attempts >= max_sessions.max(3) {
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

        self.prune_closed_yamux_sessions().await;

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
            "正在补充 {}：创建 {} 条 Yamux session（当前：{}）",
            self.manager_name, to_create, current_size
        );

        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SESSION_CONNECTS));
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
                    debug!("{} Yamux session 创建失败：{}", self.manager_name, e);
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
            warn!("{} 补充 Yamux session 失败：{}", self.manager_name, err);
            return Err(err);
        }

        if failure_count > 0 {
            debug!(
                "{} 补充 Yamux session 部分失败：成功 {} 条，失败 {} 条",
                self.manager_name, success_count, failure_count
            );
        }

        Ok(success_count)
    }

    async fn ensure_additional_yamux_session(&self, max_sessions: usize) -> Result<usize> {
        if max_sessions == 0 {
            return Ok(0);
        }

        self.prune_closed_yamux_sessions().await;

        let current_size = self.yamux_sessions.lock().await.len();
        if current_size >= max_sessions {
            return Ok(0);
        }

        self.ensure_yamux_sessions((current_size + 1).min(max_sessions))
            .await
    }

    async fn next_yamux_session_with_capacity(&self) -> Option<YamuxSessionHandle> {
        let sessions = self.yamux_sessions.lock().await;
        if sessions.is_empty() {
            return None;
        }

        let start = self.yamux_next_index.fetch_add(1, Ordering::AcqRel) % sessions.len();
        for offset in 0..sessions.len() {
            let index = (start + offset) % sessions.len();
            if sessions[index].connection.has_immediate_stream_capacity() {
                return Some(sessions[index].clone());
            }
        }

        None
    }

    async fn next_yamux_session(&self) -> Option<YamuxSessionHandle> {
        let sessions = self.yamux_sessions.lock().await;
        if sessions.is_empty() {
            return None;
        }

        let index = self.yamux_next_index.fetch_add(1, Ordering::AcqRel) % sessions.len();
        for offset in 0..sessions.len() {
            let index = (index + offset) % sessions.len();
            if !sessions[index].connection.is_closed() {
                return Some(sessions[index].clone());
            }
        }

        None
    }

    async fn remove_yamux_session(&self, session_id: usize) {
        let removed = {
            let mut sessions = self.yamux_sessions.lock().await;
            sessions
                .iter()
                .position(|session| session.id == session_id)
                .map(|index| sessions.remove(index))
        };

        if let Some(session) = removed {
            session.connection.close().await;
        }
    }

    async fn prune_closed_yamux_sessions(&self) -> usize {
        let removed = {
            let mut sessions = self.yamux_sessions.lock().await;
            let mut removed = Vec::new();
            let mut index = 0usize;
            while index < sessions.len() {
                if sessions[index].connection.is_closed() {
                    removed.push(sessions.remove(index));
                } else {
                    index += 1;
                }
            }
            removed
        };

        for session in &removed {
            debug!(
                "移除已关闭的 {} Yamux session={}",
                self.manager_name, session.id
            );
            session.connection.close().await;
        }

        removed.len()
    }

    pub(super) fn yamux_target_size(&self) -> usize {
        match self.yamux_transport {
            TransportProtocol::Udp => self.config.yamux.udp_session_count(),
            TransportProtocol::Tcp => 0,
        }
    }
}
