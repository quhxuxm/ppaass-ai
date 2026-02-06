use protocol::{Address, TransportProtocol};

use super::authenticated::AuthenticatedConnection;
use super::config::ClientConnectionConfig;
use super::stream::ClientStream;

/// A unified client connection that performs both auth and connect in one operation
/// Used primarily by proxy to connect to upstream proxy
pub struct ClientConnection {
    stream_id: String,
    stream: ClientStream,
}

impl ClientConnection {
    /// Establish a connection to a remote proxy with a target address
    pub async fn connect<C>(
        config: &C,
        target_address: Address,
        transport: TransportProtocol,
    ) -> Result<Self, std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        let auth_conn = AuthenticatedConnection::authenticate_only(config).await?;
        let (stream, stream_id) = auth_conn
            .connect_to_target(target_address, transport)
            .await?;

        Ok(Self { stream_id, stream })
    }

    /// Convert into an AsyncRead + AsyncWrite stream
    pub fn into_stream(self) -> ClientStream {
        self.stream
    }

    /// Get the stream ID
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
}
