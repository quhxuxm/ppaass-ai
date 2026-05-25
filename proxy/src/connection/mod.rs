mod agent_io;
mod auth;
mod connect;
mod egress;
mod relay;
mod response_sink;
mod responses;
mod target;
mod udp_relay;
mod udp_relay_flow;
mod upstream;
mod yamux;
mod yamux_session;

pub use agent_io::AgentIo;
pub use egress::EgressState;
pub use response_sink::BytesToProxyResponseSink;
// UpstreamConnection 在 ServerConnection 定义之后于文件末尾导出

use crate::bandwidth::BandwidthMonitor;
use crate::config::{ProxyConfig, UserConfig};
use crate::connection::target::target_addr_for_address;
use crate::connection::upstream::UpstreamConnection;
use crate::connection::yamux::{handle_yamux_tcp_stream, handle_yamux_udp_stream};
use crate::connection_limiter::{
    ConnectionLimiter, IdleConnectionPermit, UdpRelayBufferedBytesPermit, UdpRelayFlowPermit,
};
use crate::error::{ProxyError, Result};
use bytes::Bytes;
use common::{DEFAULT_STREAM_RELAY_BUFFER_SIZE, DatagramStreamIo, TcpTransportMode, spawn_guarded};
use futures::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use protocol::{
    Address, AuthRequest, AuthResponse, CipherState, CompressionMode, ConnectRequest,
    ConnectResponse, ProxyCodec, ProxyRequest, ProxyResponse, TransportProtocol, UdpRelayPacket,
    crypto::{AesGcmCipher, RsaKeyPair},
    read_yamux_connect_request, write_yamux_connect_response,
};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::codec::Framed;
use tokio_util::io::{SinkWriter, StreamReader};
use tokio_yamux::{session::Session, stream::StreamHandle};
use tracing::{debug, error, instrument, trace, warn};

type FramedWriter = SplitSink<Framed<TcpStream, ProxyCodec>, ProxyResponse>;
type FramedReader = SplitStream<Framed<TcpStream, ProxyCodec>>;

pub struct ServerConnection {
    writer: FramedWriter,
    reader: FramedReader,
    user_config: Option<UserConfig>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    cipher_state: Arc<CipherState>,
    pending_auth_request: Option<AuthRequest>,
    proxy_config: Arc<ProxyConfig>,
    egress_state: Arc<EgressState>,
    connection_limiter: ConnectionLimiter,
}

impl ServerConnection {
    pub fn new(
        stream: TcpStream,
        bandwidth_monitor: Arc<BandwidthMonitor>,
        compression_mode: CompressionMode,
        proxy_config: Arc<ProxyConfig>,
        egress_state: Arc<EgressState>,
        connection_limiter: ConnectionLimiter,
    ) -> Self {
        // 每条 agent TCP 连接都有独立的编解码器和加密状态。
        let cipher_state = Arc::new(CipherState::with_compression(compression_mode));
        let framed = Framed::new(stream, ProxyCodec::new(Some(cipher_state.clone())));
        let (writer, reader) = framed.split();

        Self {
            writer,
            reader,
            user_config: None,
            bandwidth_monitor,
            cipher_state,
            pending_auth_request: None,
            proxy_config,
            egress_state,
            connection_limiter,
        }
    }
}
