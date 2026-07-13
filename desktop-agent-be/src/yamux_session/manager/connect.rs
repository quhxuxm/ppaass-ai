use super::*;
use crate::yamux_session::proxy_connection::new_direct_tcp_target_stream;
use common::TransportMode;

impl YamuxSessionManager {
    #[instrument(skip(self))]
    pub async fn connect_to_target(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<YamuxTargetStream> {
        if self.config.transport_mode == TransportMode::Quic {
            return self.open_quic_target_stream(address, transport).await;
        }

        if transport == TransportProtocol::Tcp && self.yamux_transport == TransportProtocol::Tcp {
            let (stream, stream_id) = new_direct_tcp_target_stream(
                &self.config,
                self.get_proxy_bind_ip(),
                self.get_proxy_bind_interface(),
                address,
            )
            .await?;
            return Ok(YamuxTargetStream::new_direct(stream, stream_id));
        }

        if transport != self.yamux_transport {
            return Err(AgentError::Connection(format!(
                "{} only handles {:?} traffic, got {:?}",
                self.manager_name, self.yamux_transport, transport
            )));
        }

        self.open_target_stream(address, transport).await
    }

    async fn open_quic_target_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<YamuxTargetStream> {
        for attempt in 0..2 {
            let connection = {
                let mut current = self.quic_connection.lock().await;
                if current.as_ref().is_none_or(QuicClientConnection::is_closed) {
                    let adapter = crate::yamux_session::proxy_connection::AgentClientConfig::new(
                        &self.config,
                        self.get_proxy_bind_ip(),
                        self.get_proxy_bind_interface(),
                    );
                    *current = Some(
                        QuicClientConnection::connect(&adapter)
                            .await
                            .map_err(|err| AgentError::Connection(err.to_string()))?,
                    );
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
            match connection
                .connect_to_target(&adapter, address.clone(), transport)
                .await
            {
                Ok((stream, stream_id)) => {
                    return Ok(YamuxTargetStream::new_quic(stream, stream_id));
                }
                Err(err) if attempt == 0 && connection.is_closed() => {
                    *self.quic_connection.lock().await = None;
                    warn!("QUIC proxy 连接已关闭，重新握手后重试：{err}");
                }
                Err(err) => return Err(AgentError::Connection(err.to_string())),
            }
        }
        Err(AgentError::Connection("QUIC proxy 连接失败".to_string()))
    }
}
