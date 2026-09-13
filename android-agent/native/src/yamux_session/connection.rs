use super::*;

impl AndroidYamuxSessionManager {
    pub async fn connect_to_target(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<AndroidYamuxTargetStream> {
        let route = proxy_stream_route(self.config.transport_mode, self.yamux_transport, transport)
            .ok_or_else(|| {
                AndroidAgentError::Connection(format!(
                    "Android {} only supports {:?} proxy streams",
                    self.manager_name, self.yamux_transport
                ))
            })?;

        match route {
            ProxyStreamRoute::DirectTcp => self.open_direct_tcp_stream(address).await,
            ProxyStreamRoute::NativeUdp => self.open_udp_stream(address, transport).await,
            ProxyStreamRoute::Auto => {
                let slot_index = self.next_udp_session_slot();
                if self.auto_udp_fallback_to_yamux[slot_index].load(Ordering::Acquire) {
                    return self.open_target_stream(address, transport).await;
                }
                match self
                    .open_udp_stream_in_slot(address.clone(), transport, slot_index)
                    .await
                {
                    Ok(stream) => Ok(stream),
                    Err(err) if is_native_udp_timeout(&err) => {
                        self.auto_udp_fallback_to_yamux[slot_index].store(true, Ordering::Release);
                        warn!(
                            slot = slot_index,
                            "Android automatic UDP session timed out; switching only this session slot to TCP/Yamux"
                        );
                        debug!(
                            slot = slot_index,
                            error = %err,
                            "Android automatic UDP session timeout details"
                        );
                        self.open_target_stream(address, transport).await
                    }
                    Err(err) => Err(err),
                }
            }
            ProxyStreamRoute::Yamux => self.open_target_stream(address, transport).await,
        }
    }

    pub(super) async fn open_udp_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<AndroidYamuxTargetStream> {
        if self.shutdown.is_cancelled() {
            return Err(AndroidAgentError::Connection(
                "Android agent is stopping".into(),
            ));
        }
        if self.udp_sessions.is_empty() {
            return Err(AndroidAgentError::Connection(format!(
                "Android {} native UDP transport is disabled",
                self.manager_name
            )));
        }
        let slot_index = self.next_udp_session_slot();
        self.open_udp_stream_in_slot(address, transport, slot_index)
            .await
    }

    pub(super) async fn open_udp_stream_in_slot(
        &self,
        address: Address,
        transport: TransportProtocol,
        slot_index: usize,
    ) -> Result<AndroidYamuxTargetStream> {
        for attempt in 0..2 {
            let handle = self.ensure_udp_session(slot_index).await?;
            match handle
                .connection
                .connect_to_target(address.clone(), transport)
                .await
            {
                Ok((stream, _)) => return Ok(AndroidYamuxTargetStream::Udp(stream)),
                Err(err) if attempt == 0 && handle.connection.is_closed() => {
                    // 只移除本次失败的旧连接。singleflight 初始化完成后，其他
                    // 并发任务可能已经取得了新 handle，不能无条件清空 slot。
                    self.udp_sessions[slot_index]
                        .invalidate_if(|current| current.id == handle.id)
                        .await;
                    warn!(
                        manager = self.manager_name,
                        slot = slot_index,
                        connection_id = handle.id,
                        "Android native UDP proxy session closed; rebuilding only this pool slot"
                    );
                    debug!(
                        manager = self.manager_name,
                        slot = slot_index,
                        connection_id = handle.id,
                        error = %err,
                        "Android native UDP proxy session close details"
                    );
                }
                Err(err) => return Err(AndroidAgentError::Io(err)),
            }
        }
        Err(AndroidAgentError::Connection(
            "Android native UDP proxy session failed".into(),
        ))
    }

    async fn ensure_udp_session(&self, slot_index: usize) -> Result<AndroidUdpSession> {
        let config = self.config.clone();
        let shutdown = self.shutdown.clone();
        let manager_name = self.manager_name;
        let next_session_id = self.udp_next_session_id.clone();
        let handle = self.udp_sessions[slot_index]
            .get_or_initialize(
                |handle| !handle.connection.is_closed(),
                move || async move {
                    let connection = tokio::select! {
                        _ = shutdown.cancelled() => {
                            return Err(AndroidAgentError::Connection(
                                "Android agent is stopping".into(),
                            ));
                        }
                        result = UdpClientConnection::connect(config.as_ref()) => {
                            result.map_err(AndroidAgentError::Io)?
                        }
                    };
                    let connection_id = next_session_id.fetch_add(1, Ordering::AcqRel);
                    debug!(
                        manager = manager_name,
                        slot = slot_index,
                        connection_id,
                        "Android native encrypted UDP session pool slot established"
                    );
                    Ok::<AndroidUdpSession, AndroidAgentError>(AndroidUdpSession {
                        id: connection_id,
                        connection,
                    })
                },
            )
            .await?;
        if self.config.transport_mode.automatically_falls_back_to_tcp()
            && handle.connection.timed_out()
        {
            return Err(AndroidAgentError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "原生 UDP 会话保活响应超时",
            )));
        }
        Ok(handle)
    }

    /// Background authentication avoids charging the first UDP flow for the
    /// AuthInit/AuthOk round trip. It ends immediately during shutdown.
    pub fn prewarm_native_udp_sessions(self: &Arc<Self>) {
        for slot_index in 0..self.udp_sessions.len() {
            let manager = Arc::clone(self);
            tokio::spawn(async move {
                if let Err(error) = manager.ensure_udp_session(slot_index).await {
                    debug!(
                        manager = manager.manager_name,
                        slot = slot_index,
                        "Android native UDP session pool prewarm failed; the first flow will retry: {error}"
                    );
                }
            });
        }
    }

    #[doc(hidden)]
    pub fn next_udp_session_slot(&self) -> usize {
        // AndroidAgentConfig 已把 pool size 夹到至少 1，因此这里不会除以 0。
        self.udp_next_index.fetch_add(1, Ordering::AcqRel) % self.udp_sessions.len()
    }

    pub(super) async fn open_direct_tcp_stream(
        &self,
        address: Address,
    ) -> Result<AndroidYamuxTargetStream> {
        let target = target_label(&address);
        let timeout_duration = self.direct_tcp_stream_timeout();
        let connect = async {
            let _permit = self.direct_tcp_connects.acquire().await.map_err(|_| {
                AndroidAgentError::Connection("Android TCP connect limiter closed".into())
            })?;
            let (stream, _stream_id) = AuthenticatedConnection::connect_target(
                self.config.as_ref(),
                address,
                TransportProtocol::Tcp,
            )
            .await
            .map_err(|err| AndroidAgentError::Connection(err.to_string()))?;
            Ok(AndroidYamuxTargetStream::Direct(stream))
        };

        match tokio::time::timeout(timeout_duration, connect).await {
            Ok(result) => result,
            Err(_) => {
                debug!(
                    "Android TCP proxy stream timed out target={} after {:?}",
                    target, timeout_duration
                );
                Err(AndroidAgentError::Connection(format!(
                    "Android TCP proxy stream timed out after {} seconds",
                    timeout_duration.as_secs()
                )))
            }
        }
    }

    pub(super) fn direct_tcp_stream_timeout(&self) -> Duration {
        Duration::from_secs(self.config.connect_timeout_secs.clamp(
            MIN_DIRECT_TCP_STREAM_TIMEOUT_SECS,
            MAX_DIRECT_TCP_STREAM_TIMEOUT_SECS,
        ))
    }
}
