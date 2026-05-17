use protocol::{Address, TransportProtocol};

use super::authenticated::AuthenticatedConnection;
use super::config::ClientConnectionConfig;
use super::stream::ClientStream;

/// 统一的客户端连接，在一次操作中完成认证和连接
/// 主要供代理连接上游代理时使用
pub struct ClientConnection {
    stream_id: String,
    stream: ClientStream,
}

impl ClientConnection {
    /// 建立到远端代理的连接，并指定目标地址
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

    /// 转换为 AsyncRead + AsyncWrite 流
    pub fn into_stream(self) -> ClientStream {
        self.stream
    }

    /// 获取流 ID
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
}
