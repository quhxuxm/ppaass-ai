use super::*;
use crate::yamux_session::proxy_connection::new_direct_tcp_target_stream;

impl YamuxSessionManager {
    #[instrument(skip(self))]
    pub async fn connect_to_target(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<YamuxTargetStream> {
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
}
