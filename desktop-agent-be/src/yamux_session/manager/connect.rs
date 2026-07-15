use super::*;
use crate::yamux_session::proxy_connection::new_direct_tcp_target_stream;
use common::TransportMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyStreamRoute {
    DirectTcp,
    Quic,
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
        TransportProtocol::Udp if mode.uses_quic_for(transport) => ProxyStreamRoute::Quic,
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
        // 只决定 UDP 数据是否改用 QUIC。先校验 manager 类型，避免误调用
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
            ProxyStreamRoute::Quic => self.open_quic_target_stream(address, transport).await,
            ProxyStreamRoute::Yamux => self.open_target_stream(address, transport).await,
            ProxyStreamRoute::InvalidManager => Err(AgentError::Connection(format!(
                "{} only handles {:?} traffic, got {:?}",
                self.manager_name, self.yamux_transport, transport
            ))),
        }
    }

    async fn open_quic_target_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<YamuxTargetStream> {
        if self.quic_connections.is_empty() {
            return Err(AgentError::Connection(format!(
                "{} QUIC transport is disabled",
                self.manager_name
            )));
        }
        let slot_index = self.next_quic_connection_slot();
        for attempt in 0..2 {
            let handle = {
                let mut current = self.quic_connections[slot_index].lock().await;
                if current
                    .as_ref()
                    .is_none_or(|handle| handle.connection.is_closed())
                {
                    let adapter = crate::yamux_session::proxy_connection::AgentClientConfig::new(
                        &self.config,
                        self.get_proxy_bind_ip(),
                        self.get_proxy_bind_interface(),
                    );
                    let connection = QuicClientConnection::connect(&adapter)
                        .await
                        .map_err(|err| AgentError::Connection(err.to_string()))?;
                    let connection_id = self.quic_next_connection_id.fetch_add(1, Ordering::AcqRel);
                    debug!(
                        manager = self.manager_name,
                        slot = slot_index,
                        connection_id,
                        "QUIC 连接池 slot 已建立"
                    );
                    *current = Some(QuicConnectionHandle {
                        id: connection_id,
                        connection,
                    });
                }
                current
                    .as_ref()
                    .expect("QUIC connection initialized")
                    .clone()
            };

            let adapter = crate::yamux_session::proxy_connection::AgentClientConfig::new(
                &self.config,
                self.get_proxy_bind_ip(),
                self.get_proxy_bind_interface(),
            );
            match handle
                .connection
                .connect_to_target(&adapter, address.clone(), transport)
                .await
            {
                Ok((stream, stream_id)) => {
                    return Ok(YamuxTargetStream::new_quic(stream, stream_id));
                }
                Err(err) if attempt == 0 && handle.connection.is_closed() => {
                    let stats = handle.connection.stats();
                    let mut current = self.quic_connections[slot_index].lock().await;
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
                        rtt_ms = stats.path.rtt.as_millis(),
                        cwnd = stats.path.cwnd,
                        lost_packets = stats.path.lost_packets,
                        congestion_events = stats.path.congestion_events,
                        "QUIC proxy 连接已关闭，仅重建当前 pool slot 后重试：{err}"
                    );
                }
                Err(err) => return Err(AgentError::Connection(err.to_string())),
            }
        }
        Err(AgentError::Connection("QUIC proxy 连接失败".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_mode_routes_tcp_direct_and_udp_over_quic() {
        assert_eq!(
            proxy_stream_route(
                TransportMode::Quic,
                TransportProtocol::Tcp,
                TransportProtocol::Tcp,
            ),
            ProxyStreamRoute::DirectTcp
        );
        assert_eq!(
            proxy_stream_route(
                TransportMode::Quic,
                TransportProtocol::Udp,
                TransportProtocol::Udp,
            ),
            ProxyStreamRoute::Quic
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
    fn mismatched_manager_is_rejected_before_transport_selection() {
        assert_eq!(
            proxy_stream_route(
                TransportMode::Quic,
                TransportProtocol::Tcp,
                TransportProtocol::Udp,
            ),
            ProxyStreamRoute::InvalidManager
        );
        assert_eq!(
            proxy_stream_route(
                TransportMode::Quic,
                TransportProtocol::Udp,
                TransportProtocol::Tcp,
            ),
            ProxyStreamRoute::InvalidManager
        );
    }
}
