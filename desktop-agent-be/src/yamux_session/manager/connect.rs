use super::*;
use crate::yamux_session::proxy_connection::new_direct_tcp_target_stream;
use common::TransportMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyStreamRoute {
    Auto,
    DirectTcp,
    NativeUdp,
    Yamux,
    InvalidManager,
}

fn proxy_stream_route(
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
                let (stream, stream_id) = new_direct_tcp_target_stream(
                    &self.config,
                    self.get_proxy_bind_ip(),
                    self.get_proxy_bind_interface(),
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
            let handle = {
                let mut current = self.udp_sessions[slot_index].lock().await;
                if self.config.transport_mode.automatically_falls_back_to_tcp()
                    && current
                        .as_ref()
                        .is_some_and(|handle| handle.connection.timed_out())
                {
                    return Err(AgentError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "原生 UDP 会话保活响应超时",
                    )));
                }
                if current
                    .as_ref()
                    .is_none_or(|handle| handle.connection.is_closed())
                {
                    let adapter = crate::yamux_session::proxy_connection::AgentClientConfig::new(
                        &self.config,
                        self.get_proxy_bind_ip(),
                        self.get_proxy_bind_interface(),
                    );
                    let connection = UdpClientConnection::connect(&adapter)
                        .await
                        .map_err(AgentError::Io)?;
                    let connection_id = self.udp_next_session_id.fetch_add(1, Ordering::AcqRel);
                    debug!(
                        manager = self.manager_name,
                        slot = slot_index,
                        connection_id,
                        "原生加密 UDP 会话池 slot 已建立"
                    );
                    *current = Some(UdpSessionHandle {
                        id: connection_id,
                        connection,
                    });
                }
                current.as_ref().expect("UDP session initialized").clone()
            };

            match handle
                .connection
                .connect_to_target(address.clone(), transport)
                .await
            {
                Ok((stream, stream_id)) => {
                    return Ok(YamuxTargetStream::new_udp(stream, stream_id));
                }
                Err(err) if attempt == 0 && handle.connection.is_closed() => {
                    let mut current = self.udp_sessions[slot_index].lock().await;
                    // 只移除本次失败的旧连接。并发任务可能已经在该 slot 建立了
                    // 新连接，不能像旧实现那样无条件清空它。
                    if current
                        .as_ref()
                        .is_some_and(|current| current.id == handle.id)
                    {
                        *current = None;
                    }
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
}

fn is_native_udp_timeout(error: &AgentError) -> bool {
    match error {
        AgentError::Io(error) => error.kind() == std::io::ErrorKind::TimedOut,
        AgentError::Connection(message) => {
            message.contains("原生 UDP 认证响应超时") || message.contains("连接原生 UDP proxy 超时")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_mode_routes_tcp_direct_and_udp_over_native_udp() {
        assert_eq!(
            proxy_stream_route(
                TransportMode::Udp,
                TransportProtocol::Tcp,
                TransportProtocol::Tcp,
            ),
            ProxyStreamRoute::DirectTcp
        );
        assert_eq!(
            proxy_stream_route(
                TransportMode::Udp,
                TransportProtocol::Udp,
                TransportProtocol::Udp,
            ),
            ProxyStreamRoute::NativeUdp
        );
    }

    #[test]
    fn tcp_mode_routes_tcp_direct_and_udp_over_yamux() {
        assert_eq!(
            proxy_stream_route(
                TransportMode::Tcp,
                TransportProtocol::Tcp,
                TransportProtocol::Tcp,
            ),
            ProxyStreamRoute::DirectTcp
        );
        assert_eq!(
            proxy_stream_route(
                TransportMode::Tcp,
                TransportProtocol::Udp,
                TransportProtocol::Udp,
            ),
            ProxyStreamRoute::Yamux
        );
    }

    #[test]
    fn auto_mode_routes_udp_through_runtime_fallback_path() {
        assert_eq!(
            proxy_stream_route(
                TransportMode::Auto,
                TransportProtocol::Udp,
                TransportProtocol::Udp,
            ),
            ProxyStreamRoute::Auto
        );
        assert!(is_native_udp_timeout(&AgentError::Connection(
            "原生 UDP 认证响应超时".into()
        )));
        assert!(!is_native_udp_timeout(&AgentError::Connection(
            "authentication failed".into()
        )));
    }

    #[test]
    fn mismatched_manager_is_rejected_before_transport_selection() {
        assert_eq!(
            proxy_stream_route(
                TransportMode::Udp,
                TransportProtocol::Tcp,
                TransportProtocol::Udp,
            ),
            ProxyStreamRoute::InvalidManager
        );
        assert_eq!(
            proxy_stream_route(
                TransportMode::Udp,
                TransportProtocol::Udp,
                TransportProtocol::Tcp,
            ),
            ProxyStreamRoute::InvalidManager
        );
    }
}
