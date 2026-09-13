use super::*;
use crate::yamux_session::proxy_connection::new_direct_tcp_target_stream;
use common::TransportMode;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyStreamRoute {
    Auto,
    DirectTcp,
    NativeUdp,
    Yamux,
    InvalidManager,
}

pub fn proxy_stream_route(
    mode: TransportMode,
    manager_transport: TransportProtocol,
    transport: TransportProtocol,
) -> ProxyStreamRoute {
    if transport != manager_transport {
        return ProxyStreamRoute::InvalidManager;
    }

    match transport {
        TransportProtocol::Tcp => ProxyStreamRoute::DirectTcp,
        TransportProtocol::Udp if mode.automatically_falls_back_to_tcp() => ProxyStreamRoute::Auto,
        TransportProtocol::Udp if mode.uses_native_udp_for(transport) => {
            ProxyStreamRoute::NativeUdp
        }
        TransportProtocol::Udp => ProxyStreamRoute::Yamux,
    }
}

impl YamuxSessionManager {
    #[instrument(skip(self))]
    pub async fn connect_to_target(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<YamuxTargetStream> {
        // TCP 数据始终使用原有的 direct framed TCP 路径，transport_mode
        // 只决定 UDP 数据是否改用原生加密 UDP。先校验 manager 类型，避免误调用
        // 绕过 TCP/UDP 语义隔离。
        match proxy_stream_route(self.config.transport_mode, self.yamux_transport, transport) {
            ProxyStreamRoute::DirectTcp => {
                let route = self.current_proxy_route();
                let (stream, stream_id) = new_direct_tcp_target_stream(
                    &self.config,
                    &route.addrs,
                    route.bind_ip,
                    route.bind_interface,
                    self.proxy_affinity.clone(),
                    address,
                )
                .await?;
                Ok(YamuxTargetStream::new_direct(stream, stream_id))
            }
            ProxyStreamRoute::NativeUdp => self.open_udp_target_stream(address, transport).await,
            ProxyStreamRoute::Auto => {
                let slot_index = self.next_udp_session_slot();
                if self.auto_udp_fallback_to_yamux[slot_index].load(Ordering::Acquire) {
                    return self.open_target_stream(address, transport).await;
                }
                match self
                    .open_udp_target_stream_in_slot(address.clone(), transport, slot_index)
                    .await
                {
                    Ok(stream) => Ok(stream),
                    Err(err) if is_native_udp_timeout(&err) => {
                        self.auto_udp_fallback_to_yamux[slot_index].store(true, Ordering::Release);
                        warn!(
                            manager = self.manager_name,
                            slot = slot_index,
                            "自动 UDP 模式检测到原生加密 UDP session 超时，仅将该 session slot 的后续流量切换到 TCP/Yamux：{err}"
                        );
                        self.open_target_stream(address, transport).await
                    }
                    Err(err) => Err(err),
                }
            }
            ProxyStreamRoute::Yamux => self.open_target_stream(address, transport).await,
            ProxyStreamRoute::InvalidManager => Err(AgentError::Connection(format!(
                "{} only handles {:?} traffic, got {:?}",
                self.manager_name, self.yamux_transport, transport
            ))),
        }
    }

    async fn open_udp_target_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<YamuxTargetStream> {
        if self.udp_sessions.is_empty() {
            return Err(AgentError::Connection(format!(
                "{} native UDP transport is disabled",
                self.manager_name
            )));
        }
        let slot_index = self.next_udp_session_slot();
        self.open_udp_target_stream_in_slot(address, transport, slot_index)
            .await
    }

    async fn open_udp_target_stream_in_slot(
        &self,
        address: Address,
        transport: TransportProtocol,
        slot_index: usize,
    ) -> Result<YamuxTargetStream> {
        for attempt in 0..2 {
            let handle = self.ensure_udp_session(slot_index, None).await?;

            match handle
                .connection
                .connect_to_target(address.clone(), transport)
                .await
            {
                Ok((stream, stream_id)) => {
                    return Ok(YamuxTargetStream::new_udp(stream, stream_id));
                }
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
                        "原生 UDP proxy 会话已关闭，仅重建当前 pool slot 后重试：{err}"
                    );
                }
                Err(err) => return Err(AgentError::Io(err)),
            }
        }
        Err(AgentError::Connection(
            "原生 UDP proxy 会话失败".to_string(),
        ))
    }

    async fn ensure_udp_session(
        &self,
        slot_index: usize,
        shutdown: Option<CancellationToken>,
    ) -> Result<UdpSessionHandle> {
        let route = self.current_proxy_route();
        let config = self.config.clone();
        let proxy_affinity = self.proxy_affinity.clone();
        let manager_name = self.manager_name;
        let next_session_id = self.udp_next_session_id.clone();
        let handle = self.udp_sessions[slot_index]
            .get_or_initialize(
                |handle| !handle.connection.is_closed(),
                move || async move {
                    let adapter = crate::yamux_session::proxy_connection::AgentClientConfig::new_with_affinity(
                        &config,
                        &route.addrs,
                        route.bind_ip,
                        route.bind_interface,
                        proxy_affinity,
                    );
                    let connection = match shutdown {
                        Some(shutdown) => tokio::select! {
                            _ = shutdown.cancelled() => {
                                return Err(AgentError::Connection(
                                    "Agent is stopping".to_string(),
                                ));
                            }
                            result = UdpClientConnection::connect(&adapter) => {
                                result.map_err(AgentError::Io)?
                            }
                        },
                        None => UdpClientConnection::connect(&adapter)
                            .await
                            .map_err(AgentError::Io)?,
                    };
                    let connection_id = next_session_id.fetch_add(1, Ordering::AcqRel);
                    debug!(
                        manager = manager_name,
                        slot = slot_index,
                        connection_id,
                        "原生加密 UDP 会话池 slot 已建立"
                    );
                    Ok::<UdpSessionHandle, AgentError>(UdpSessionHandle {
                        id: connection_id,
                        connection,
                    })
                },
            )
            .await?;
        if self.config.transport_mode.automatically_falls_back_to_tcp()
            && handle.connection.timed_out()
        {
            return Err(AgentError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "原生 UDP 会话保活响应超时",
            )));
        }
        Ok(handle)
    }

    /// Start the configured native UDP session pool in the background so the
    /// first user datagram normally does not pay the AuthInit/AuthOk RTT.
    pub fn prewarm_native_udp_sessions(self: &Arc<Self>, shutdown: CancellationToken) {
        for slot_index in 0..self.udp_sessions.len() {
            let manager = Arc::clone(self);
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                if let Err(error) = manager.ensure_udp_session(slot_index, Some(shutdown)).await {
                    debug!(
                        manager = manager.manager_name,
                        slot = slot_index,
                        "原生 UDP 会话池预热失败，将在首个 UDP flow 时重试：{error}"
                    );
                }
            });
        }
    }
}

pub fn is_native_udp_timeout(error: &AgentError) -> bool {
    match error {
        AgentError::Io(error) => error.kind() == std::io::ErrorKind::TimedOut,
        AgentError::Connection(message) => {
            message.contains("原生 UDP 认证响应超时") || message.contains("连接原生 UDP proxy 超时")
        }
        _ => false,
    }
}
