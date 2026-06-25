use super::*;

impl ConnectionPool {
    #[instrument(skip(self))]
    pub async fn get_connected_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<ConnectedStream> {
        if transport != self.yamux_transport {
            return Err(AgentError::Connection(format!(
                "{} only handles {:?} traffic, got {:?}",
                self.pool_name, self.yamux_transport, transport
            )));
        }

        self.get_yamux_connected_stream(address, transport).await
    }
}
