//! 单条 agent 连接的协议状态机。
//!
//! `server` 模块接入的是 TCP socket；进入这里后，socket 会被 `ProxyCodec`
//! 包装成 PPAASS 协议帧。认证成功前只接受 `Auth`，认证成功后等待第一个
//! `Connect`，随后根据目标类型进入 legacy relay、UDP relay 或 Yamux session。

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
use common::{DatagramStreamIo, TcpTransportMode, spawn_guarded};
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

// proxy 与 agent 之间的协议帧缓冲只负责吸收短时突发，不替代 relay 的背压。
// HLS/视频分片常见“目标站点瞬时下发一大段、agent 侧稍后消费”的形态；
// 过小的 64KB 边界会很快把背压推回 CDN，浏览器侧看起来像读取停顿。
const PROXY_FRAMED_INITIAL_CAPACITY: usize = 32 * 1024;
const PROXY_FRAMED_BACKPRESSURE_BOUNDARY: usize = 512 * 1024;

pub struct ServerConnection {
    // 写回 agent 的协议响应流。所有 ConnectResponse/Data 都从这里出去。
    writer: FramedWriter,
    // 从 agent 读入的协议请求流。认证、Connect、Data 都从这里进入。
    reader: FramedReader,
    // 认证成功后保存用户配置；relay 阶段用它做带宽统计和限速判断。
    user_config: Option<UserConfig>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    // 每条外层 TCP 连接独立一份加密状态：认证前无 AES，认证后设置 AES cipher。
    cipher_state: Arc<CipherState>,
    // `peek_auth_username` 会先读走 AuthRequest，这里暂存给后续 authenticate 继续校验。
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
        // compression_mode 在连接创建时确定，AES cipher 在认证成功后再写入同一个 state。
        let cipher_state = Arc::new(CipherState::with_compression(compression_mode));
        let framed = proxy_framed_stream(stream, ProxyCodec::new(Some(cipher_state.clone())));
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

fn proxy_framed_stream(stream: TcpStream, codec: ProxyCodec) -> Framed<TcpStream, ProxyCodec> {
    // 协议 framed 缓冲仍然是有界的，只把边界放大到能容纳几个媒体 DataPacket 的量级。
    // 这样能吸收 CDN 下发的短时 burst，又不会像无界队列那样在慢客户端后面积压内存。
    let mut framed = Framed::with_capacity(stream, codec, PROXY_FRAMED_INITIAL_CAPACITY);
    framed.set_backpressure_boundary(PROXY_FRAMED_BACKPRESSURE_BOUNDARY);
    framed
}
