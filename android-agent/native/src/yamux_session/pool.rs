use super::*;

impl AndroidYamuxSessionManager {
    pub(super) async fn open_target_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<AndroidYamuxTargetStream> {
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
                        AndroidAgentError::Connection(
                            "no available Android Yamux proxy session".into(),
                        )
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
                Ok((stream, _stream_id)) => return Ok(AndroidYamuxTargetStream::Yamux(stream)),
                Err(err) => {
                    let message = err.to_string();
                    if is_yamux_session_capacity_error(&message) {
                        if self.ensure_additional_yamux_session(max_sessions).await? > 0 {
                            continue;
                        }
                        attempts += 1;
                        if attempts >= max_sessions.max(3) {
                            return Err(AndroidAgentError::Connection(message));
                        }
                        tokio::task::yield_now().await;
                        continue;
                    }

                    if is_yamux_actual_target_connect_error(&message) {
                        return Err(AndroidAgentError::Connection(message));
                    }
                    warn!(
                        manager = self.manager_name,
                        session_id = session.id,
                        "Android Yamux session unusable; retrying"
                    );
                    debug!(
                        manager = self.manager_name,
                        session_id = session.id,
                        error = %message,
                        "Android Yamux session failure details"
                    );
                    self.remove_yamux_session(session.id).await;
                    attempts += 1;
                    if attempts >= max_sessions.max(3) {
                        return Err(AndroidAgentError::Connection(message));
                    }
                }
            }
        }
    }

    pub(super) async fn ensure_yamux_sessions(&self, target_size: usize) -> Result<usize> {
        if self.shutdown.is_cancelled() || target_size == 0 {
            return Ok(0);
        }

        self.prune_closed_yamux_sessions().await;

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
            "refilling Android {}: creating {} Yamux sessions (current={})",
            self.manager_name, to_create, current_size
        );

        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SESSION_CONNECTS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..to_create {
            let config = self.config.clone();
            let semaphore = semaphore.clone();
            let transport = self.yamux_transport;
            let yamux_settings = config.yamux.udp_settings();
            let session_id = self.yamux_next_session_id.fetch_add(1, Ordering::AcqRel);
            set.spawn(async move {
                let _permit = semaphore.acquire().await.ok();
                YamuxClientConnection::connect_for(config.as_ref(), transport, yamux_settings)
                    .await
                    .map(|connection| AndroidYamuxSession {
                        id: session_id,
                        connection,
                    })
                    .map_err(|err| AndroidAgentError::Connection(err.to_string()))
            });
        }

        let mut success_count = 0usize;
        let mut failure_count = 0usize;
        let mut last_error = None;
        while let Some(result) = set.join_next().await {
            match result {
                Ok(Ok(session)) => {
                    let mut sessions = self.yamux_sessions.lock().await;
                    if sessions.len() >= target_size {
                        set.abort_all();
                        break;
                    }
                    sessions.push(session);
                    success_count += 1;
                }
                Ok(Err(err)) => {
                    debug!(
                        "failed to create Android {} Yamux session: {err}",
                        self.manager_name
                    );
                    failure_count += 1;
                    last_error = Some(err);
                }
                Err(err) if err.is_cancelled() => {}
                Err(err) => {
                    warn!(
                        manager = self.manager_name,
                        "Android Yamux refill task join failed"
                    );
                    debug!(
                        manager = self.manager_name,
                        error = %err,
                        "Android Yamux refill task join failure details"
                    );
                }
            }
        }

        if success_count == 0 && self.yamux_sessions.lock().await.is_empty() {
            let err = last_error.unwrap_or_else(|| {
                AndroidAgentError::Connection("failed to create Android Yamux session".into())
            });
            warn!(
                manager = self.manager_name,
                "failed to refill Android Yamux"
            );
            debug!(
                manager = self.manager_name,
                error = %err,
                "Android Yamux refill failure details"
            );
            return Err(err);
        }

        if failure_count > 0 {
            debug!(
                "partially refilled Android {} Yamux: {} succeeded, {} failed",
                self.manager_name, success_count, failure_count
            );
        }

        Ok(success_count)
    }

    pub(super) async fn ensure_additional_yamux_session(
        &self,
        max_sessions: usize,
    ) -> Result<usize> {
        if self.shutdown.is_cancelled() || max_sessions == 0 {
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

    pub(super) async fn next_yamux_session_with_capacity(&self) -> Option<AndroidYamuxSession> {
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

    pub(super) async fn next_yamux_session(&self) -> Option<AndroidYamuxSession> {
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

    pub(super) async fn remove_yamux_session(&self, session_id: usize) {
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

    pub(super) async fn prune_closed_yamux_sessions(&self) -> usize {
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
                "pruning closed Android {} Yamux session {}",
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
