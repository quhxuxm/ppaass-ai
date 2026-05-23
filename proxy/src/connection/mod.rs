mod agent_io;
mod egress;
mod response_sink;
mod upstream;

pub use agent_io::AgentIo;
pub use egress::EgressState;
pub use response_sink::BytesToProxyResponseSink;
// UpstreamConnection 在 ServerConnection 定义之后于文件末尾导出

use crate::bandwidth::BandwidthMonitor;
use crate::config::{ProxyConfig, UserConfig};
use crate::connection::upstream::UpstreamConnection;
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
use std::collections::HashMap;
#[cfg(not(windows))]
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
#[cfg(windows)]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use std::ptr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::codec::Framed;
use tokio_util::io::{SinkWriter, StreamReader};
use tokio_yamux::{session::Session, stream::StreamHandle};
use tracing::{debug, error, instrument, trace, warn};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};

type FramedWriter = SplitSink<Framed<TcpStream, ProxyCodec>, ProxyResponse>;
type FramedReader = SplitStream<Framed<TcpStream, ProxyCodec>>;

struct UdpRelayFlow {
    tx: tokio::sync::mpsc::Sender<QueuedUdpRelayData>,
}

struct QueuedUdpRelayData {
    data: Vec<u8>,
    _buffer_permit: UdpRelayBufferedBytesPermit,
}

struct QueuedUdpRelayResponse {
    packet: UdpRelayPacket,
    _buffer_permit: UdpRelayBufferedBytesPermit,
}

fn udp_relay_channel_size(config: &ProxyConfig) -> usize {
    config.udp_relay_channel_size.max(1)
}

fn try_acquire_udp_relay_buffer(
    limiter: &ConnectionLimiter,
    max_buffered_bytes: usize,
    flow_id: u64,
    bytes: usize,
    direction: &str,
) -> Option<UdpRelayBufferedBytesPermit> {
    match limiter.try_acquire_udp_relay_buffered_bytes(bytes) {
        Some(permit) => Some(permit),
        None => {
            warn!(
                "proxy UDP relay 缓冲字节数已达上限（当前={}，上限={}），丢弃 flow {} 的{}数据包（{} bytes）",
                limiter.active_udp_relay_buffered_bytes(),
                max_buffered_bytes,
                flow_id,
                direction,
                bytes
            );
            None
        }
    }
}

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

    async fn read_request(&mut self) -> Result<Option<ProxyRequest>> {
        // 统一把协议层读错误转换为 proxy 错误，调用方只处理业务分支。
        match self.reader.next().await {
            Some(Ok(req)) => Ok(Some(req)),
            Some(Err(e)) => Err(ProxyError::Protocol(protocol::ProtocolError::Io(e))),
            None => Ok(None), // 连接已关闭
        }
    }

    /// 在不完成认证的情况下窥探认证请求并获取用户名
    #[instrument(skip(self))]
    pub async fn peek_auth_username(&mut self) -> Result<String> {
        // 接收认证请求
        // 第一个请求始终应为 AuthRequest（认证请求）？
        let request = match self.read_request().await? {
            Some(req) => req,
            None => return Err(ProxyError::Connection("Connection closed".to_string())),
        };

        if let ProxyRequest::Auth(auth_request) = request {
            // 先取出用户名用于查配置，完整 AuthRequest 留到 authenticate 中校验。
            let username = auth_request.username.clone();
            debug!(
                "[认证请求] username={}, timestamp={}, encrypted_aes_key_len={}",
                auth_request.username,
                auth_request.timestamp,
                auth_request.encrypted_aes_key.len()
            );
            // 保存认证请求，稍后继续使用
            self.pending_auth_request = Some(auth_request);
            Ok(username)
        } else {
            Err(ProxyError::Authentication(
                "Expected auth request".to_string(),
            ))
        }
    }

    /// 发送认证错误响应
    #[instrument(skip(self))]
    pub async fn send_auth_error(&mut self, message: &str) -> Result<()> {
        let auth_response = AuthResponse {
            success: false,
            message: message.to_string(),
            session_id: None,
        };

        self.send_response(ProxyResponse::Auth(auth_response)).await
    }

    #[instrument(skip(self, proxy_config, user_config))]
    pub async fn authenticate(
        &mut self,
        proxy_config: &ProxyConfig,
        user_config: UserConfig,
    ) -> Result<()> {
        debug!("正在认证用户连接：{}", user_config.username);

        // 使用 peek_auth_username 中读取到的待处理认证请求
        let auth_request = self
            .pending_auth_request
            .take()
            .ok_or_else(|| ProxyError::Authentication("No pending auth request".to_string()))?;

        debug!(
            "[认证请求] 正在处理：username={}, timestamp={}, encrypted_aes_key_len={}, encrypted_aes_key_hex={}",
            auth_request.username,
            auth_request.timestamp,
            auth_request.encrypted_aes_key.len(),
            hex::encode(&auth_request.encrypted_aes_key)
        );

        // 校验用户名是否匹配
        if auth_request.username != user_config.username {
            self.send_auth_error("Username mismatch").await?;
            return Err(ProxyError::Authentication("Username mismatch".to_string()));
        }

        // 校验时间戳以防止重放攻击
        let current_time = common::current_timestamp();
        if (current_time - auth_request.timestamp).abs() > proxy_config.replay_attack_tolerance {
            // 5 分钟容忍窗口
            self.send_auth_error("Timestamp expired").await?;
            return Err(ProxyError::Authentication("Timestamp expired".to_string()));
        }

        // 使用用户公钥解密 AES 密钥
        let user_public_key = RsaKeyPair::from_public_key_pem(&user_config.public_key_pem)
            .map_err(|e| ProxyError::Authentication(format!("Invalid public key: {}", e)))?;

        let aes_key_bytes = protocol::crypto::decrypt_with_public_key(
            &user_public_key,
            &auth_request.encrypted_aes_key,
        )
        .map_err(|e| {
            error!("解密 AES 密钥失败：{}", e);
            ProxyError::Authentication(format!("Failed to decrypt AES key: {}", e))
        })?;

        debug!(
            "[认证请求] 已解密 AES key_len={}, aes_key_hex={}",
            aes_key_bytes.len(),
            hex::encode(&aes_key_bytes)
        );

        // 转换为固定长度数组
        let aes_key: [u8; 32] = aes_key_bytes
            .try_into()
            .map_err(|_| ProxyError::Authentication("Invalid AES key length".to_string()))?;

        let aes_cipher = AesGcmCipher::from_key(aes_key);

        let session_id = common::generate_id();

        // 发送认证响应
        let auth_response = AuthResponse {
            success: true,
            message: "Authentication successful".to_string(),
            session_id: Some(session_id.clone()),
        };

        debug!(
            "[认证响应] 正在发送：成功=true，会话 ID={:?}",
            auth_response.session_id
        );

        self.send_response(ProxyResponse::Auth(auth_response))
            .await?;

        self.user_config = Some(user_config);

        // 更新后续消息使用的加密状态
        self.cipher_state.set_cipher(Arc::new(aes_cipher));

        debug!("认证成功");
        Ok(())
    }

    async fn send_response(&mut self, response: ProxyResponse) -> Result<()> {
        // 所有响应都经过 framed writer，统一走协议编码、压缩和加密。
        self.writer
            .send(response)
            .await
            .map_err(|e| ProxyError::Connection(format!("Failed to send response: {}", e)))?;
        Ok(())
    }

    pub async fn handle_pre_connect_request(
        &mut self,
        pre_connect_idle_timeout: Duration,
        username: &str,
        mut idle_permit: Option<IdleConnectionPermit>,
    ) -> Result<()> {
        // 只在“认证完成但还没收到第一个 Connect”的阶段使用 idle 超时。
        // 一旦 Connect 到达，就移交给具体的 relay / Yamux session，不再用该超时杀外层连接。
        loop {
            let request =
                match tokio::time::timeout(pre_connect_idle_timeout, self.read_request()).await {
                    Ok(result) => result?,
                    Err(_) => {
                        warn!(
                            "用户 '{}' 的预热连接等待 Connect 超时（{} 秒），正在关闭以防止泄漏",
                            username,
                            pre_connect_idle_timeout.as_secs()
                        );
                        return Ok(());
                    }
                };

            match request {
                Some(ProxyRequest::Connect(connect_request)) => {
                    // 从这里开始，这条 agent 连接不再算作“已认证但未 Connect”的 idle 连接。
                    // 如果它是 Yamux 外层 session，不应再被 pre-connect idle timeout 杀掉；
                    // 每条 Yamux 子流会在 relay 层应用 yamux_tcp_relay_idle_timeout_secs。
                    drop(idle_permit.take());
                    debug!(
                        "[连接请求] 请求 ID={}，地址={:?}，传输协议={:?}",
                        connect_request.request_id,
                        connect_request.address,
                        connect_request.transport
                    );
                    self.handle_connect(connect_request).await?;
                    // 中继结束（连接关闭）后，返回以关闭连接
                    return Ok(());
                }
                Some(ProxyRequest::Auth(auth_request)) => {
                    debug!("处理循环中收到意外认证请求：{:?}", auth_request.username);
                }
                Some(_) => {
                    error!("连接请求之前收到意外请求类型");
                }
                None => return Ok(()), // Agent 连接已关闭
            }
        }
    }

    async fn handle_connect(&mut self, connect_request: ConnectRequest) -> Result<()> {
        debug!("连接请求：{:?}", connect_request.address);

        // 检查用户带宽限制
        if let Some(user_config) = &self.user_config
            && !self
                .bandwidth_monitor
                .check_limit(&user_config.username)
                .await
        {
            return self
                .send_connect_error(
                    connect_request.request_id,
                    "Bandwidth limit exceeded".to_string(),
                )
                .await;
        }

        if matches!(connect_request.address, Address::TcpYamux) {
            if self.proxy_config.transport.tcp_mode == TcpTransportMode::Legacy {
                return self
                    .send_connect_error(
                        connect_request.request_id,
                        "TCP Yamux is disabled by proxy config".to_string(),
                    )
                    .await;
            }
            if connect_request.transport != TransportProtocol::Tcp {
                return self
                    .send_connect_error(
                        connect_request.request_id,
                        "TCP Yamux only supports TCP transport".to_string(),
                    )
                    .await;
            }
            self.send_connect_success(connect_request.request_id.clone(), "TCP Yamux connected")
                .await?;
            // Yamux 外层 session 是一条长期复用的控制/数据通道；不要套 pre-connect idle。
            // 死连接由 Yamux keepalive 发现；TCP 子流空闲策略由 yamux_tcp_relay_idle_timeout_secs 控制。
            return self
                .handle_tcp_yamux_connect(connect_request.request_id)
                .await;
        }

        if matches!(connect_request.address, Address::UdpYamux) {
            if self.proxy_config.transport.udp_mode == TcpTransportMode::Legacy {
                return self
                    .send_connect_error(
                        connect_request.request_id,
                        "UDP Yamux is disabled by proxy config".to_string(),
                    )
                    .await;
            }
            if connect_request.transport != TransportProtocol::Udp {
                return self
                    .send_connect_error(
                        connect_request.request_id,
                        "UDP Yamux only supports UDP transport".to_string(),
                    )
                    .await;
            }
            self.send_connect_success(connect_request.request_id.clone(), "UDP Yamux connected")
                .await?;
            return self
                .handle_udp_yamux_connect(connect_request.request_id)
                .await;
        }

        if matches!(connect_request.address, Address::UdpRelay) {
            if connect_request.transport != TransportProtocol::Udp {
                return self
                    .send_connect_error(
                        connect_request.request_id,
                        "UDP relay only supports UDP transport".to_string(),
                    )
                    .await;
            }
            if self.proxy_config.forward_mode {
                return self.handle_upstream_connect(connect_request).await;
            }
            return self.handle_udp_relay_connect(connect_request).await;
        }

        // 检查是否启用了转发模式
        if self.proxy_config.forward_mode {
            return self.handle_upstream_connect(connect_request).await;
        }

        let target_addr = self.target_addr_for_request(&connect_request.address)?;
        match connect_request.transport {
            TransportProtocol::Tcp => self.handle_tcp_connect(connect_request, &target_addr).await,
            TransportProtocol::Udp => self.handle_udp_connect(connect_request, &target_addr).await,
        }
    }

    fn target_addr_for_request(&self, address: &Address) -> Result<String> {
        // ProxyDns 是特殊地址类型，需要在 proxy 端决定真正的 DNS 上游。
        target_addr_for_address(&self.proxy_config, address)
    }

    async fn handle_upstream_connect(&mut self, connect_request: ConnectRequest) -> Result<()> {
        debug!("正在将请求转发到上游代理");

        // 转发模式下 proxy 作为客户端连接下一跳 proxy，再把 agent 流量接过去。
        match UpstreamConnection::connect(
            &self.proxy_config,
            connect_request.address.clone(),
            connect_request.transport,
        )
        .await
        {
            Ok(upstream_conn) => {
                debug!("已连接到上游代理");
                // 只有上游连接成功后才回复 agent 连接成功。
                self.send_connect_success(
                    connect_request.request_id.clone(),
                    "Connected through upstream",
                )
                .await?;

                let mut stream = upstream_conn.into_stream();
                // 上游连接也是一个 AsyncRead/AsyncWrite，复用普通 TCP 中继逻辑。
                self.relay(connect_request.request_id, &mut stream).await?;
            }
            Err(e) => {
                error!("连接上游代理失败：{}", e);
                self.send_connect_error(
                    connect_request.request_id,
                    format!("Upstream error: {}", e),
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn handle_tcp_connect(
        &mut self,
        connect_request: ConnectRequest,
        target_addr: &str,
    ) -> Result<()> {
        // 通过启动时共享的出站状态连接目标，避免每次请求重新读取路由表。
        let connect_timeout = Duration::from_secs(self.proxy_config.connect_timeout_secs);
        match tokio::time::timeout(connect_timeout, self.egress_state.connect_tcp(target_addr))
            .await
        {
            Ok(Ok(mut target_stream)) => {
                debug!(
                    "已连接到目标（TCP）：{}，出站设备={}",
                    target_addr,
                    self.proxy_config
                        .outbound_interface
                        .as_deref()
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or("默认路由")
                );
                self.send_connect_success(connect_request.request_id.clone(), "Connected")
                    .await?;
                self.relay(connect_request.request_id, &mut target_stream)
                    .await?;
            }
            Ok(Err(e)) => {
                warn!("连接目标失败（TCP）：{}，目标={}", e, target_addr);
                self.send_connect_error(
                    connect_request.request_id,
                    format!("Failed to connect: {}", e),
                )
                .await?;
            }
            Err(_) => {
                warn!(
                    "连接目标超时（TCP）：目标={}，超时={} 秒",
                    target_addr, self.proxy_config.connect_timeout_secs
                );
                self.send_connect_error(
                    connect_request.request_id,
                    format!(
                        "Connect timeout after {} seconds",
                        self.proxy_config.connect_timeout_secs
                    ),
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn handle_tcp_yamux_connect(&mut self, stream_id: String) -> Result<()> {
        debug!("正在建立 TCP Yamux 会话：stream_id={stream_id}");

        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();
        let stream_id_filter = stream_id.clone();

        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        let stream = (&mut self.reader)
            .take_while(move |res| {
                let continue_stream = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        !(packet.stream_id == stream_id_stop
                            && packet.is_end
                            && packet.data.is_empty())
                    }
                    Ok(_) => true,
                    Err(_) => false,
                };
                futures::future::ready(continue_stream)
            })
            .filter_map(move |res| {
                let user = username_stream.as_ref();
                let monitor = &monitor_stream;

                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        if packet.stream_id == stream_id_filter && !packet.data.is_empty() {
                            if let Some(u) = user {
                                monitor.record_received(u, packet.data.len() as u64);
                            }
                            Some(Ok(Bytes::from(packet.data)))
                        } else {
                            None
                        }
                    }
                    Ok(_) => None,
                    Err(e) => Some(Err(io::Error::other(e))),
                };

                futures::future::ready(result)
            });

        let writer = SinkWriter::new(sink);
        let reader = StreamReader::new(stream);
        let agent_io = AgentIo { reader, writer };
        let mut session = Session::new_server(
            agent_io,
            self.proxy_config.yamux.tcp_settings().to_tokio_config(),
        );
        let proxy_config = self.proxy_config.clone();
        let egress_state = self.egress_state.clone();
        let bandwidth_monitor = self.bandwidth_monitor.clone();
        let username = self.user_config.as_ref().map(|c| c.username.clone());

        while let Some(result) = session.next().await {
            match result {
                Ok(stream) => {
                    let proxy_config = proxy_config.clone();
                    let egress_state = egress_state.clone();
                    let bandwidth_monitor = bandwidth_monitor.clone();
                    let username = username.clone();
                    spawn_guarded("proxy yamux tcp stream", async move {
                        if let Err(err) = handle_yamux_tcp_stream(
                            stream,
                            proxy_config,
                            egress_state,
                            bandwidth_monitor,
                            username,
                        )
                        .await
                        {
                            debug!("Yamux TCP 子流已结束：{err}");
                        }
                    });
                }
                Err(err) => {
                    debug!("TCP Yamux 会话结束 stream_id={stream_id}: {err}");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_udp_yamux_connect(&mut self, stream_id: String) -> Result<()> {
        debug!("正在建立 UDP Yamux 会话：stream_id={stream_id}");

        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();
        let stream_id_filter = stream_id.clone();

        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        let stream = (&mut self.reader)
            .take_while(move |res| {
                let continue_stream = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        !(packet.stream_id == stream_id_stop
                            && packet.is_end
                            && packet.data.is_empty())
                    }
                    Ok(_) => true,
                    Err(_) => false,
                };
                futures::future::ready(continue_stream)
            })
            .filter_map(move |res| {
                let user = username_stream.as_ref();
                let monitor = &monitor_stream;

                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        if packet.stream_id == stream_id_filter && !packet.data.is_empty() {
                            if let Some(u) = user {
                                monitor.record_received(u, packet.data.len() as u64);
                            }
                            Some(Ok(Bytes::from(packet.data)))
                        } else {
                            None
                        }
                    }
                    Ok(_) => None,
                    Err(e) => Some(Err(io::Error::other(e))),
                };

                futures::future::ready(result)
            });

        let writer = SinkWriter::new(sink);
        let reader = StreamReader::new(stream);
        let agent_io = AgentIo { reader, writer };
        let mut session = Session::new_server(
            agent_io,
            self.proxy_config.yamux.udp_settings().to_tokio_config(),
        );
        let proxy_config = self.proxy_config.clone();
        let egress_state = self.egress_state.clone();
        let bandwidth_monitor = self.bandwidth_monitor.clone();
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let connection_limiter = self.connection_limiter.clone();

        while let Some(result) = session.next().await {
            match result {
                Ok(stream) => {
                    let proxy_config = proxy_config.clone();
                    let egress_state = egress_state.clone();
                    let bandwidth_monitor = bandwidth_monitor.clone();
                    let username = username.clone();
                    let connection_limiter = connection_limiter.clone();
                    spawn_guarded("proxy yamux udp stream", async move {
                        if let Err(err) = handle_yamux_udp_stream(
                            stream,
                            proxy_config,
                            egress_state,
                            bandwidth_monitor,
                            username,
                            connection_limiter,
                        )
                        .await
                        {
                            debug!("Yamux UDP 子流已结束：{err}");
                        }
                    });
                }
                Err(err) => {
                    debug!("UDP Yamux 会话结束 stream_id={stream_id}: {err}");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_udp_relay_connect(&mut self, connect_request: ConnectRequest) -> Result<()> {
        debug!("正在建立 UDP 共享中继");
        self.send_connect_success(connect_request.request_id.clone(), "UDP relay connected")
            .await?;

        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let channel_size = udp_relay_channel_size(&self.proxy_config);
        let (response_tx, mut response_rx) =
            tokio::sync::mpsc::channel::<QueuedUdpRelayResponse>(channel_size);
        let (flow_done_tx, mut flow_done_rx) = tokio::sync::mpsc::channel::<u64>(channel_size);
        let mut flows: HashMap<u64, UdpRelayFlow> = HashMap::new();
        let max_flows = self.proxy_config.max_udp_relay_flows_per_connection;
        let stream_id = connect_request.request_id;
        let relay_idle_timeout = Duration::from_secs(self.proxy_config.udp_relay_idle_timeout_secs);
        let relay_idle = tokio::time::sleep(relay_idle_timeout);
        tokio::pin!(relay_idle);

        loop {
            tokio::select! {
                _ = &mut relay_idle => {
                    debug!(
                        "UDP 共享中继空闲超过 {} 秒，关闭该连接",
                        relay_idle_timeout.as_secs()
                    );
                    break;
                }
                request = self.reader.next() => {
                    let request = match request {
                        Some(Ok(request)) => request,
                        Some(Err(e)) => return Err(ProxyError::Protocol(protocol::ProtocolError::Io(e))),
                        None => break,
                    };

                    let ProxyRequest::Data(packet) = request else {
                        continue;
                    };
                    if packet.stream_id != stream_id {
                        continue;
                    }
                    if packet.is_end && packet.data.is_empty() {
                        break;
                    }
                    if packet.data.is_empty() {
                        continue;
                    }

                    relay_idle.as_mut().reset(tokio::time::Instant::now() + relay_idle_timeout);

                    if let Some(user) = &username {
                        self.bandwidth_monitor.record_received(user, packet.data.len() as u64);
                    }

                    let relay_packet = match UdpRelayPacket::decode(&packet.data) {
                        Ok(packet) => packet,
                        Err(e) => {
                            debug!("UDP relay 数据包解析失败：{e}");
                            continue;
                        }
                    };

                    if !flows.contains_key(&relay_packet.flow_id) {
                        if max_flows != 0 && flows.len() >= max_flows {
                            warn!(
                                "UDP relay flow 数已达上限（{}），丢弃 flow {} 的数据包",
                                max_flows, relay_packet.flow_id
                            );
                            continue;
                        }
                        let Some(flow_permit) = self.connection_limiter.try_acquire_udp_relay_flow() else {
                            warn!(
                                "proxy 全局 UDP relay flow 数已达上限（当前={}，上限={}），丢弃 flow {} 的数据包",
                                self.connection_limiter.active_udp_relay_flows(),
                                self.proxy_config.max_udp_relay_flows,
                                relay_packet.flow_id
                            );
                            continue;
                        };
                        match self.spawn_udp_relay_flow(
                            relay_packet.flow_id,
                            relay_packet.address.clone(),
                            response_tx.clone(),
                            flow_done_tx.clone(),
                            flow_permit,
                            relay_idle_timeout,
                            channel_size,
                        ).await {
                            Ok(flow) => {
                                flows.insert(relay_packet.flow_id, flow);
                            }
                            Err(e) => {
                                debug!(
                                    "UDP relay flow {} 连接目标失败：{}",
                                    relay_packet.flow_id, e
                                );
                                continue;
                            }
                        }
                    }

                    let flow_id = relay_packet.flow_id;
                    if let Some(flow) = flows.get(&flow_id) {
                        let Some(buffer_permit) = try_acquire_udp_relay_buffer(
                            &self.connection_limiter,
                            self.proxy_config.max_udp_relay_buffered_bytes,
                            flow_id,
                            relay_packet.data.len(),
                            "上行",
                        ) else {
                            continue;
                        };
                        let queued = QueuedUdpRelayData {
                            data: relay_packet.data,
                            _buffer_permit: buffer_permit,
                        };
                        match flow.tx.try_send(queued) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                debug!("UDP relay flow {flow_id} 发送队列已满，丢弃一个 UDP 数据包");
                            }
                            Err(TrySendError::Closed(_)) => {
                                flows.remove(&flow_id);
                            }
                        }
                    }
                }
                response = response_rx.recv() => {
                    let Some(response) = response else { break };
                    let encoded = response
                        .packet
                        .encode()
                        .map_err(ProxyError::Protocol)?;
                    if let Some(user) = &username {
                        self.bandwidth_monitor.record_sent(user, encoded.len() as u64);
                    }
                    let packet = protocol::DataPacket {
                        stream_id: stream_id.clone(),
                        data: encoded,
                        is_end: false,
                    };
                    self.writer
                        .send(ProxyResponse::Data(packet))
                        .await
                        .map_err(|e| ProxyError::Connection(format!("Failed to send UDP relay response: {e}")))?;
                    relay_idle.as_mut().reset(tokio::time::Instant::now() + relay_idle_timeout);
                }
                done = flow_done_rx.recv() => {
                    let Some(flow_id) = done else { break };
                    flows.remove(&flow_id);
                }
            }
        }

        debug!("UDP 共享中继已结束");
        Ok(())
    }

    async fn spawn_udp_relay_flow(
        &self,
        flow_id: u64,
        address: Address,
        response_tx: tokio::sync::mpsc::Sender<QueuedUdpRelayResponse>,
        flow_done_tx: tokio::sync::mpsc::Sender<u64>,
        flow_permit: UdpRelayFlowPermit,
        flow_idle_timeout: Duration,
        channel_size: usize,
    ) -> Result<UdpRelayFlow> {
        let target_addr = relay_target_addr(&address)?;
        let socket = self
            .egress_state
            .connect_udp(&target_addr)
            .await
            .map_err(|e| {
                ProxyError::Connection(format!("Failed to connect UDP relay target: {e}"))
            })?;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<QueuedUdpRelayData>(channel_size);
        let response_address = address.clone();
        let connection_limiter = self.connection_limiter.clone();
        let max_buffered_bytes = self.proxy_config.max_udp_relay_buffered_bytes;

        spawn_guarded("proxy udp relay flow", async move {
            let _flow_permit = flow_permit;
            let mut buf = vec![0u8; 65535];
            let idle = tokio::time::sleep(flow_idle_timeout);
            tokio::pin!(idle);

            loop {
                tokio::select! {
                    _ = &mut idle => break,
                    maybe_data = rx.recv() => {
                        let Some(queued) = maybe_data else { break };
                        let data = queued.data;
                        match tokio::time::timeout(flow_idle_timeout, socket.send(&data)).await {
                            Ok(Ok(_)) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + flow_idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("UDP relay flow {flow_id} 发送失败：{e}");
                                break;
                            }
                            Err(_) => {
                                debug!(
                                    "UDP relay flow {flow_id} 发送超过 {} 秒，关闭该 flow",
                                    flow_idle_timeout.as_secs()
                                );
                                break;
                            }
                        }
                    }
                    read = socket.recv(&mut buf) => {
                        match read {
                            Ok(n) => {
                                let Some(buffer_permit) = try_acquire_udp_relay_buffer(
                                    &connection_limiter,
                                    max_buffered_bytes,
                                    flow_id,
                                    n,
                                    "下行",
                                ) else {
                                    debug!("UDP relay flow {flow_id} 响应缓冲预算不足，关闭该 flow 以释放 socket");
                                    break;
                                };
                                let response = QueuedUdpRelayResponse {
                                    packet: UdpRelayPacket {
                                        flow_id,
                                        address: response_address.clone(),
                                        data: buf[..n].to_vec(),
                                    },
                                    _buffer_permit: buffer_permit,
                                };
                                match response_tx.try_send(response) {
                                    Ok(()) => {
                                        idle.as_mut().reset(tokio::time::Instant::now() + flow_idle_timeout);
                                    }
                                    Err(TrySendError::Full(_)) => {
                                        debug!("UDP relay flow {flow_id} 响应队列已满，关闭该 flow 以释放 socket");
                                        break;
                                    }
                                    Err(TrySendError::Closed(_)) => break,
                                }
                            }
                            Err(e) => {
                                debug!("UDP relay flow {flow_id} 接收失败：{e}");
                                break;
                            }
                        }
                    }
                }
            }
            drop(socket);
            let _ = flow_done_tx.send(flow_id).await;
            debug!("UDP relay flow {flow_id} 已结束");
        });

        Ok(UdpRelayFlow { tx })
    }

    async fn handle_udp_connect(
        &mut self,
        connect_request: ConnectRequest,
        target_addr: &str,
    ) -> Result<()> {
        debug!("正在处理 UDP 连接请求：{connect_request:?}");

        // UDP 也复用同一份出站状态，保持 TCP/UDP 的出口选择一致。
        match self.egress_state.connect_udp(target_addr).await {
            Ok(socket) => {
                debug!(
                    "已连接到目标（UDP）：{}，出站设备={}",
                    target_addr,
                    self.proxy_config
                        .outbound_interface
                        .as_deref()
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or("默认路由")
                );
                self.send_connect_success(connect_request.request_id.clone(), "Connected")
                    .await?;
                self.relay_udp(connect_request.request_id, socket).await?;
            }
            Err(e) => {
                warn!("连接目标失败（UDP）：{}，目标={}", e, target_addr);
                self.send_connect_error(
                    connect_request.request_id,
                    format!("Failed to connect UDP: {}", e),
                )
                .await?;
            }
        }

        Ok(())
    }

    #[instrument(skip(self, udp_socket))]
    async fn relay_udp(&mut self, stream_id: String, udp_socket: UdpSocket) -> Result<()> {
        // UDP 没有天然字节流，这里用 StreamReader/SinkWriter 拼成类流式中继。
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();
        let stream_id_filter = stream_id.clone();

        // 使用自定义 Sink 将 UDP 响应数据重新封装成 proxy DataPacket。
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        // 从 agent 到 UDP 的方向只消费当前 stream_id 的数据包。
        let stream = (&mut self.reader)
            .take_while(move |res| {
                let continue_stream = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        !(packet.stream_id == stream_id_stop
                            && packet.is_end
                            && packet.data.is_empty())
                    }
                    Ok(_) => true,
                    // 出错时停止流，防止连接泄漏
                    Err(_) => false,
                };
                futures::future::ready(continue_stream)
            })
            .filter_map(move |res| {
                let user = username_stream.as_ref();
                let monitor = &monitor_stream;

                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        // 只处理该流的数据包
                        trace!(
                            packet.stream_id,
                            stream_id_filter, "从 agent 收到 UDP 数据包：{packet:?}"
                        );
                        if packet.stream_id == stream_id_filter && !packet.data.is_empty() {
                            if let Some(u) = user {
                                monitor.record_received(u, packet.data.len() as u64);
                            }
                            Some(Ok(Bytes::from(packet.data)))
                        } else {
                            None
                        }
                    }
                    Ok(_) => None,
                    Err(e) => Some(Err(io::Error::other(e))),
                };

                futures::future::ready(result)
            });

        let writer = SinkWriter::new(sink);
        let reader = StreamReader::new(stream);

        // AgentIo 把“从 agent 读”和“写回 agent”合成一个双向 IO。
        let agent_io = AgentIo { reader, writer };

        let udp_socket = Arc::new(udp_socket);
        let udp_recv = udp_socket.clone();
        let udp_send = udp_socket.clone();

        let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);

        let udp_relay_idle_timeout =
            Duration::from_secs(self.proxy_config.udp_relay_idle_timeout_secs);
        let idle_timeout = tokio::time::sleep(udp_relay_idle_timeout);
        tokio::pin!(idle_timeout);
        let mut agent_buf = [0u8; 65535];
        let mut udp_buf = [0u8; 65535];

        loop {
            tokio::select! {
                _ = &mut idle_timeout => {
                    debug!(
                        "UDP 中继空闲超过 {} 秒，关闭 socket",
                        udp_relay_idle_timeout.as_secs()
                    );
                    break;
                }
                read = agent_reader.read(&mut agent_buf) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = &agent_buf[..n];
                            trace!(
                                "从 agent 收到发往目标的 UDP 数据：{:?}\n{}",
                                udp_socket.peer_addr(),
                                pretty_hex::pretty_hex(&data)
                            );
                            match tokio::time::timeout(udp_relay_idle_timeout, udp_send.send(data)).await {
                                Ok(Ok(_)) => {
                                    idle_timeout.as_mut().reset(tokio::time::Instant::now() + udp_relay_idle_timeout);
                                }
                                Ok(Err(e)) => {
                                    debug!("UDP 发送错误：{}", e);
                                    break;
                                }
                                Err(_) => {
                                    debug!("UDP 发送超过 {} 秒，关闭 socket", udp_relay_idle_timeout.as_secs());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("读取 agent 数据错误：{}", e);
                            break;
                        }
                    }
                }
                recv = udp_recv.recv(&mut udp_buf) => {
                    match recv {
                        Ok(n) => {
                            let data = &udp_buf[..n];
                            trace!(
                                "从目标收到发往 agent 的 UDP 数据：{:?}\n{}",
                                udp_socket.peer_addr(),
                                pretty_hex::pretty_hex(&data)
                            );
                            let write_result = tokio::time::timeout(udp_relay_idle_timeout, async {
                                agent_writer.write_all(data).await?;
                                agent_writer.flush().await
                            }).await;
                            match write_result {
                                Ok(Ok(())) => {
                                    idle_timeout.as_mut().reset(tokio::time::Instant::now() + udp_relay_idle_timeout);
                                }
                                Ok(Err(e)) => {
                                    debug!("写入 agent 数据错误：{}", e);
                                    break;
                                }
                                Err(_) => {
                                    debug!("写入 agent 超过 {} 秒，关闭 UDP 中继", udp_relay_idle_timeout.as_secs());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("UDP 接收错误：{}", e);
                            break;
                        }
                    }
                }
            }
        }

        debug!("UDP 中继已结束");
        Ok(())
    }

    async fn relay<S>(&mut self, stream_id: String, target_stream: &mut S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        // TCP 中继把 agent 数据包流和目标 TCP 流转换成双向字节拷贝。
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();
        let stream_id_filter = stream_id.clone();

        // 使用自定义 Sink 实现，避免 SinkExt::with 与闭包引发 HRTB 问题
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        // agent 数据流中可能混有其他消息，只取当前 stream 的 DataPacket。
        let stream = (&mut self.reader)
            .take_while(move |res| {
                let continue_stream = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        !(packet.stream_id == stream_id_stop
                            && packet.is_end
                            && packet.data.is_empty())
                    }
                    Ok(_) => true,
                    // 出错时停止流，防止连接泄漏
                    Err(_) => false,
                };
                futures::future::ready(continue_stream)
            })
            .filter_map(move |res| {
                let user = username_stream.as_ref();
                let monitor = &monitor_stream;

                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        // 只处理该流的数据包
                        if packet.stream_id == stream_id_filter {
                            if !packet.data.is_empty() {
                                if let Some(u) = user {
                                    monitor.record_received(u, packet.data.len() as u64);
                                }
                                Some(Ok(Bytes::from(packet.data)))
                            } else {
                                None
                            }
                        } else {
                            // 其他流的数据，跳过
                            None
                        }
                    }
                    Ok(_) => None, // 忽略非 Data 数据包
                    Err(e) => Some(Err(io::Error::other(e))),
                };

                futures::future::ready(result)
            });

        let writer = SinkWriter::new(sink);
        let reader = StreamReader::new(stream);

        // AgentIo 让 packet-based 的 agent 连接呈现为 AsyncRead/AsyncWrite。
        let agent_io = AgentIo { reader, writer };

        let tcp_relay_idle_timeout_secs = self.proxy_config.tcp_relay_idle_timeout_secs;
        if tcp_relay_idle_timeout_secs == 0 {
            // 兼容旧行为：不配置超时时按任一端关闭来结束中继。
            let mut agent_io = agent_io;
            match tokio::io::copy_bidirectional_with_sizes(
                target_stream,
                &mut agent_io,
                DEFAULT_STREAM_RELAY_BUFFER_SIZE,
                DEFAULT_STREAM_RELAY_BUFFER_SIZE,
            )
            .await
            {
                Ok((up, down)) => debug!("中继已结束：上行 {}，下行 {}", up, down),
                Err(e) => debug!("中继错误：{}", e),
            }
            return Ok(());
        }

        let idle_timeout = Duration::from_secs(tcp_relay_idle_timeout_secs);
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);

        let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);
        let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);
        let mut up_bytes: u64 = 0;
        let mut down_bytes: u64 = 0;
        let mut agent_buf = [0u8; DEFAULT_STREAM_RELAY_BUFFER_SIZE];
        let mut target_buf = [0u8; DEFAULT_STREAM_RELAY_BUFFER_SIZE];

        loop {
            tokio::select! {
                _ = &mut idle => {
                    debug!(
                        "TCP 中继空闲超过 {} 秒，关闭连接",
                        idle_timeout.as_secs()
                    );
                    break;
                }
                read = agent_reader.read(&mut agent_buf) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) => {
                            up_bytes += n as u64;
                            match tokio::time::timeout(idle_timeout, async {
                                target_writer.write_all(&agent_buf[..n]).await?;
                                target_writer.flush().await
                            }).await {
                                Ok(Ok(())) => {
                                    idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                                }
                                Ok(Err(e)) => {
                                    debug!("TCP relay 写入目标失败：{}", e);
                                    break;
                                }
                                Err(_) => {
                                    debug!("TCP relay 写入目标超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("TCP relay 读取 agent 数据失败：{}", e);
                            break;
                        }
                    }
                }
                read = target_reader.read(&mut target_buf) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) => {
                            down_bytes += n as u64;
                            match tokio::time::timeout(idle_timeout, async {
                                agent_writer.write_all(&target_buf[..n]).await?;
                                agent_writer.flush().await
                            }).await {
                                Ok(Ok(())) => {
                                    idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                                }
                                Ok(Err(e)) => {
                                    debug!("TCP relay 写回 agent 失败：{}", e);
                                    break;
                                }
                                Err(_) => {
                                    debug!("TCP relay 写回 agent 超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("TCP relay 读取目标数据失败：{}", e);
                            break;
                        }
                    }
                }
            }
        }

        debug!("中继已结束：上行 {}，下行 {}", up_bytes, down_bytes);

        Ok(())
    }

    async fn send_connect_error(&mut self, request_id: String, message: String) -> Result<()> {
        // connect 失败也回给 agent，避免 agent 端一直等待。
        let connect_response = ConnectResponse {
            request_id,
            success: false,
            message,
        };

        self.send_response(ProxyResponse::Connect(connect_response))
            .await
    }

    async fn send_connect_success(&mut self, request_id: String, message: &str) -> Result<()> {
        // connect 成功后，agent 才会开始发送该 stream 的数据。
        let connect_response = ConnectResponse {
            request_id,
            success: true,
            message: message.to_string(),
        };

        self.send_response(ProxyResponse::Connect(connect_response))
            .await
    }
}

async fn handle_yamux_tcp_stream(
    mut stream: StreamHandle,
    proxy_config: Arc<ProxyConfig>,
    egress_state: Arc<EgressState>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    username: Option<String>,
) -> Result<()> {
    let connect_request = read_yamux_connect_request(&mut stream).await?;
    debug!(
        "[Yamux 连接请求] 请求 ID={}，地址={:?}，传输协议={:?}",
        connect_request.request_id, connect_request.address, connect_request.transport
    );

    if connect_request.transport != TransportProtocol::Tcp {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Yamux substream only supports TCP transport".to_string(),
        )
        .await?;
        return Ok(());
    }

    if matches!(
        connect_request.address,
        Address::TcpYamux | Address::UdpYamux | Address::UdpRelay
    ) {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Yamux substream target must be a TCP address".to_string(),
        )
        .await?;
        return Ok(());
    }

    if let Some(username) = &username
        && !bandwidth_monitor.check_limit(username).await
    {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Bandwidth limit exceeded".to_string(),
        )
        .await?;
        return Ok(());
    }

    if proxy_config.forward_mode {
        return handle_yamux_upstream_connect(stream, connect_request, proxy_config).await;
    }

    let target_addr = match target_addr_for_address(&proxy_config, &connect_request.address) {
        Ok(target_addr) => target_addr,
        Err(err) => {
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!("Failed to resolve target: {err}"),
            )
            .await?;
            return Ok(());
        }
    };

    let connect_timeout = Duration::from_secs(proxy_config.connect_timeout_secs);
    match tokio::time::timeout(connect_timeout, egress_state.connect_tcp(&target_addr)).await {
        Ok(Ok(target_stream)) => {
            debug!(
                "已通过 Yamux 子流连接目标（TCP）：{}，出站设备={}",
                target_addr,
                proxy_config
                    .outbound_interface
                    .as_deref()
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or("默认路由")
            );
            send_yamux_connect_success(&mut stream, connect_request.request_id, "Connected")
                .await?;
            relay_yamux_tcp_stream(
                stream,
                target_stream,
                proxy_config.yamux_tcp_relay_idle_timeout_secs,
            )
            .await?;
        }
        Ok(Err(e)) => {
            warn!("Yamux 子流连接目标失败（TCP）：{}，目标={}", e, target_addr);
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!("Failed to connect: {}", e),
            )
            .await?;
        }
        Err(_) => {
            warn!(
                "Yamux 子流连接目标超时（TCP）：目标={}，超时={} 秒",
                target_addr, proxy_config.connect_timeout_secs
            );
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!(
                    "Connect timeout after {} seconds",
                    proxy_config.connect_timeout_secs
                ),
            )
            .await?;
        }
    }

    Ok(())
}

async fn handle_yamux_udp_stream(
    mut stream: StreamHandle,
    proxy_config: Arc<ProxyConfig>,
    egress_state: Arc<EgressState>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    username: Option<String>,
    connection_limiter: ConnectionLimiter,
) -> Result<()> {
    let connect_request = read_yamux_connect_request(&mut stream).await?;
    debug!(
        "[Yamux UDP 连接请求] 请求 ID={}，地址={:?}，传输协议={:?}",
        connect_request.request_id, connect_request.address, connect_request.transport
    );

    if connect_request.transport != TransportProtocol::Udp {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Yamux UDP substream only supports UDP transport".to_string(),
        )
        .await?;
        return Ok(());
    }

    if matches!(
        connect_request.address,
        Address::TcpYamux | Address::UdpYamux
    ) {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Yamux UDP substream target must not be a Yamux outer address".to_string(),
        )
        .await?;
        return Ok(());
    }

    if let Some(username) = &username
        && !bandwidth_monitor.check_limit(username).await
    {
        send_yamux_connect_error(
            &mut stream,
            connect_request.request_id,
            "Bandwidth limit exceeded".to_string(),
        )
        .await?;
        return Ok(());
    }

    if proxy_config.forward_mode {
        match UpstreamConnection::connect(
            &proxy_config,
            connect_request.address.clone(),
            connect_request.transport,
        )
        .await
        {
            Ok(upstream_conn) => {
                send_yamux_connect_success(
                    &mut stream,
                    connect_request.request_id,
                    "Connected through upstream",
                )
                .await?;
                relay_yamux_udp_byte_stream(
                    stream,
                    upstream_conn.into_stream(),
                    proxy_config.udp_relay_idle_timeout_secs,
                )
                .await?;
            }
            Err(e) => {
                error!("Yamux UDP 子流连接上游代理失败：{}", e);
                send_yamux_connect_error(
                    &mut stream,
                    connect_request.request_id,
                    format!("Upstream error: {}", e),
                )
                .await?;
            }
        }
        return Ok(());
    }

    if matches!(connect_request.address, Address::UdpRelay) {
        send_yamux_connect_success(
            &mut stream,
            connect_request.request_id,
            "UDP relay connected",
        )
        .await?;
        relay_yamux_udp_relay_stream(
            stream,
            proxy_config,
            egress_state,
            bandwidth_monitor,
            username,
            connection_limiter,
        )
        .await?;
        return Ok(());
    }

    let target_addr = match target_addr_for_address(&proxy_config, &connect_request.address) {
        Ok(target_addr) => target_addr,
        Err(err) => {
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!("Failed to resolve target: {err}"),
            )
            .await?;
            return Ok(());
        }
    };

    let connect_timeout = Duration::from_secs(proxy_config.connect_timeout_secs);
    match tokio::time::timeout(connect_timeout, egress_state.connect_udp(&target_addr)).await {
        Ok(Ok(socket)) => {
            debug!(
                "已通过 Yamux 子流连接目标（UDP）：{}，出站设备={}",
                target_addr,
                proxy_config
                    .outbound_interface
                    .as_deref()
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or("默认路由")
            );
            send_yamux_connect_success(&mut stream, connect_request.request_id, "Connected")
                .await?;
            relay_yamux_udp_stream(stream, socket, proxy_config.udp_relay_idle_timeout_secs)
                .await?;
        }
        Ok(Err(e)) => {
            warn!("Yamux 子流连接目标失败（UDP）：{}，目标={}", e, target_addr);
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!("Failed to connect UDP: {}", e),
            )
            .await?;
        }
        Err(_) => {
            warn!(
                "Yamux 子流连接目标超时（UDP）：目标={}，超时={} 秒",
                target_addr, proxy_config.connect_timeout_secs
            );
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!(
                    "Connect timeout after {} seconds",
                    proxy_config.connect_timeout_secs
                ),
            )
            .await?;
        }
    }

    Ok(())
}

async fn handle_yamux_upstream_connect(
    mut stream: StreamHandle,
    connect_request: ConnectRequest,
    proxy_config: Arc<ProxyConfig>,
) -> Result<()> {
    debug!("正在将 Yamux 子流请求转发到上游代理");
    match UpstreamConnection::connect(
        &proxy_config,
        connect_request.address.clone(),
        connect_request.transport,
    )
    .await
    {
        Ok(upstream_conn) => {
            send_yamux_connect_success(
                &mut stream,
                connect_request.request_id,
                "Connected through upstream",
            )
            .await?;
            relay_yamux_tcp_stream(
                stream,
                upstream_conn.into_stream(),
                proxy_config.yamux_tcp_relay_idle_timeout_secs,
            )
            .await?;
        }
        Err(e) => {
            error!("Yamux 子流连接上游代理失败：{}", e);
            send_yamux_connect_error(
                &mut stream,
                connect_request.request_id,
                format!("Upstream error: {}", e),
            )
            .await?;
        }
    }

    Ok(())
}

async fn relay_yamux_tcp_stream<S>(
    mut agent_stream: StreamHandle,
    mut target_stream: S,
    idle_timeout_secs: u64,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    if idle_timeout_secs == 0 {
        match tokio::io::copy_bidirectional_with_sizes(
            &mut agent_stream,
            &mut target_stream,
            DEFAULT_STREAM_RELAY_BUFFER_SIZE,
            DEFAULT_STREAM_RELAY_BUFFER_SIZE,
        )
        .await
        {
            Ok((up, down)) => debug!("Yamux 子流中继已结束：上行 {}，下行 {}", up, down),
            Err(e) => debug!("Yamux 子流中继错误：{}", e),
        }
        return Ok(());
    }

    let idle_timeout = Duration::from_secs(idle_timeout_secs);
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_stream);
    let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;
    let mut agent_buf = [0u8; DEFAULT_STREAM_RELAY_BUFFER_SIZE];
    let mut target_buf = [0u8; DEFAULT_STREAM_RELAY_BUFFER_SIZE];

    loop {
        tokio::select! {
            _ = &mut idle => {
                debug!(
                    "Yamux TCP 子流空闲超过 {} 秒，关闭连接",
                    idle_timeout.as_secs()
                );
                break;
            }
            read = agent_reader.read(&mut agent_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        up_bytes += n as u64;
                        match tokio::time::timeout(idle_timeout, async {
                            target_writer.write_all(&agent_buf[..n]).await?;
                            target_writer.flush().await
                        }).await {
                            Ok(Ok(())) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux TCP relay 写入目标失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux TCP relay 写入目标超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux TCP relay 读取 agent 数据失败：{}", e);
                        break;
                    }
                }
            }
            read = target_reader.read(&mut target_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        down_bytes += n as u64;
                        match tokio::time::timeout(idle_timeout, async {
                            agent_writer.write_all(&target_buf[..n]).await?;
                            agent_writer.flush().await
                        }).await {
                            Ok(Ok(())) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux TCP relay 写回 agent 失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux TCP relay 写回 agent 超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux TCP relay 读取目标数据失败：{}", e);
                        break;
                    }
                }
            }
        }
    }

    debug!(
        "Yamux 子流中继已结束：上行 {}，下行 {}",
        up_bytes, down_bytes
    );
    Ok(())
}

async fn relay_yamux_udp_byte_stream<S>(
    agent_stream: StreamHandle,
    mut target_stream: S,
    idle_timeout_secs: u64,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut agent_io = DatagramStreamIo::new(agent_stream);
    if idle_timeout_secs == 0 {
        match tokio::io::copy_bidirectional(&mut agent_io, &mut target_stream).await {
            Ok((up, down)) => debug!("Yamux UDP 字节中继已结束：上行 {}，下行 {}", up, down),
            Err(e) => debug!("Yamux UDP 字节中继错误：{}", e),
        }
        return Ok(());
    }

    let idle_timeout = Duration::from_secs(idle_timeout_secs);
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);
    let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;
    let mut agent_buf = vec![0u8; 65535];
    let mut target_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = &mut idle => {
                debug!(
                    "Yamux UDP 字节中继空闲超过 {} 秒，关闭连接",
                    idle_timeout.as_secs()
                );
                break;
            }
            read = agent_reader.read(&mut agent_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        up_bytes += n as u64;
                        match tokio::time::timeout(idle_timeout, async {
                            target_writer.write_all(&agent_buf[..n]).await?;
                            target_writer.flush().await
                        }).await {
                            Ok(Ok(())) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux UDP 字节中继写入目标失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux UDP 字节中继写入目标超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux UDP 字节中继读取 agent 数据失败：{}", e);
                        break;
                    }
                }
            }
            read = target_reader.read(&mut target_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        down_bytes += n as u64;
                        match tokio::time::timeout(idle_timeout, async {
                            agent_writer.write_all(&target_buf[..n]).await?;
                            agent_writer.flush().await
                        }).await {
                            Ok(Ok(())) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux UDP 字节中继写回 agent 失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux UDP 字节中继写回 agent 超过 {} 秒，关闭连接", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux UDP 字节中继读取目标数据失败：{}", e);
                        break;
                    }
                }
            }
        }
    }

    debug!(
        "Yamux UDP 字节中继已结束：上行 {}，下行 {}",
        up_bytes, down_bytes
    );
    Ok(())
}

async fn relay_yamux_udp_stream(
    agent_stream: StreamHandle,
    udp_socket: UdpSocket,
    idle_timeout_secs: u64,
) -> Result<()> {
    let agent_io = DatagramStreamIo::new(agent_stream);
    let udp_socket = Arc::new(udp_socket);
    let udp_recv = udp_socket.clone();
    let udp_send = udp_socket.clone();
    let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);
    let idle_timeout = Duration::from_secs(idle_timeout_secs);
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let mut agent_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = &mut idle => {
                debug!(
                    "Yamux UDP 子流空闲超过 {} 秒，关闭 socket",
                    idle_timeout.as_secs()
                );
                break;
            }
            read = agent_reader.read(&mut agent_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        match tokio::time::timeout(idle_timeout, udp_send.send(&agent_buf[..n])).await {
                            Ok(Ok(_)) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux UDP 子流发送目标失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux UDP 子流发送目标超过 {} 秒，关闭 socket", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux UDP 子流读取 agent 数据失败：{}", e);
                        break;
                    }
                }
            }
            recv = udp_recv.recv(&mut udp_buf) => {
                match recv {
                    Ok(n) => {
                        match tokio::time::timeout(idle_timeout, async {
                            agent_writer.write_all(&udp_buf[..n]).await?;
                            agent_writer.flush().await
                        }).await {
                            Ok(Ok(())) => {
                                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            Ok(Err(e)) => {
                                debug!("Yamux UDP 子流写回 agent 失败：{}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("Yamux UDP 子流写回 agent 超过 {} 秒，关闭 socket", idle_timeout.as_secs());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Yamux UDP 子流读取目标失败：{}", e);
                        break;
                    }
                }
            }
        }
    }

    debug!("Yamux UDP 子流已结束");
    Ok(())
}

async fn relay_yamux_udp_relay_stream(
    agent_stream: StreamHandle,
    proxy_config: Arc<ProxyConfig>,
    egress_state: Arc<EgressState>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    username: Option<String>,
    connection_limiter: ConnectionLimiter,
) -> Result<()> {
    let agent_io = DatagramStreamIo::new(agent_stream);
    let (mut reader, mut writer) = tokio::io::split(agent_io);
    let channel_size = udp_relay_channel_size(&proxy_config);
    let (response_tx, mut response_rx) =
        tokio::sync::mpsc::channel::<QueuedUdpRelayResponse>(channel_size);
    let (flow_done_tx, mut flow_done_rx) = tokio::sync::mpsc::channel::<u64>(channel_size);
    let mut flows: HashMap<u64, UdpRelayFlow> = HashMap::new();
    let max_flows = proxy_config.max_udp_relay_flows_per_connection;
    let relay_idle_timeout = Duration::from_secs(proxy_config.udp_relay_idle_timeout_secs);
    let relay_idle = tokio::time::sleep(relay_idle_timeout);
    tokio::pin!(relay_idle);
    let mut request_buf = vec![0u8; 1024 * 1024];

    loop {
        tokio::select! {
            _ = &mut relay_idle => {
                debug!(
                    "Yamux UDP 共享中继空闲超过 {} 秒，关闭该子流",
                    relay_idle_timeout.as_secs()
                );
                break;
            }
            read = reader.read(&mut request_buf) => {
                let n = match read {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        debug!("Yamux UDP 共享中继读取失败：{e}");
                        break;
                    }
                };

                relay_idle.as_mut().reset(tokio::time::Instant::now() + relay_idle_timeout);
                if let Some(user) = &username {
                    bandwidth_monitor.record_received(user, n as u64);
                }

                let relay_packet = match UdpRelayPacket::decode(&request_buf[..n]) {
                    Ok(packet) => packet,
                    Err(e) => {
                        debug!("Yamux UDP relay 数据包解析失败：{e}");
                        continue;
                    }
                };

                if !flows.contains_key(&relay_packet.flow_id) {
                    if max_flows != 0 && flows.len() >= max_flows {
                        warn!(
                            "Yamux UDP relay flow 数已达上限（{}），丢弃 flow {} 的数据包",
                            max_flows, relay_packet.flow_id
                        );
                        continue;
                    }
                    let Some(flow_permit) = connection_limiter.try_acquire_udp_relay_flow() else {
                        warn!(
                            "proxy 全局 UDP relay flow 数已达上限（当前={}，上限={}），丢弃 flow {} 的数据包",
                            connection_limiter.active_udp_relay_flows(),
                            proxy_config.max_udp_relay_flows,
                            relay_packet.flow_id
                        );
                        continue;
                    };
                    match spawn_yamux_udp_relay_flow(
                        egress_state.clone(),
                        relay_packet.flow_id,
                        relay_packet.address.clone(),
                        response_tx.clone(),
                        flow_done_tx.clone(),
                        flow_permit,
                        relay_idle_timeout,
                        channel_size,
                        connection_limiter.clone(),
                        proxy_config.max_udp_relay_buffered_bytes,
                    ).await {
                        Ok(flow) => {
                            flows.insert(relay_packet.flow_id, flow);
                        }
                        Err(e) => {
                            debug!(
                                "Yamux UDP relay flow {} 连接目标失败：{}",
                                relay_packet.flow_id, e
                            );
                            continue;
                        }
                    }
                }

                let flow_id = relay_packet.flow_id;
                if let Some(flow) = flows.get(&flow_id) {
                    let Some(buffer_permit) = try_acquire_udp_relay_buffer(
                        &connection_limiter,
                        proxy_config.max_udp_relay_buffered_bytes,
                        flow_id,
                        relay_packet.data.len(),
                        "上行",
                    ) else {
                        continue;
                    };
                    let queued = QueuedUdpRelayData {
                        data: relay_packet.data,
                        _buffer_permit: buffer_permit,
                    };
                    match flow.tx.try_send(queued) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            debug!("Yamux UDP relay flow {flow_id} 发送队列已满，丢弃一个 UDP 数据包");
                        }
                        Err(TrySendError::Closed(_)) => {
                            flows.remove(&flow_id);
                        }
                    }
                }
            }
            response = response_rx.recv() => {
                let Some(response) = response else { break };
                let encoded = response
                    .packet
                    .encode()
                    .map_err(ProxyError::Protocol)?;
                if let Some(user) = &username {
                    bandwidth_monitor.record_sent(user, encoded.len() as u64);
                }
                match tokio::time::timeout(relay_idle_timeout, async {
                    writer.write_all(&encoded).await?;
                    writer.flush().await
                }).await {
                    Ok(Ok(())) => {
                        relay_idle.as_mut().reset(tokio::time::Instant::now() + relay_idle_timeout);
                    }
                    Ok(Err(e)) => {
                        debug!("Yamux UDP relay 响应写回失败：{e}");
                        break;
                    }
                    Err(_) => {
                        debug!("Yamux UDP relay 响应写回超过 {} 秒，关闭该子流", relay_idle_timeout.as_secs());
                        break;
                    }
                }
            }
            done = flow_done_rx.recv() => {
                let Some(flow_id) = done else { break };
                flows.remove(&flow_id);
            }
        }
    }

    debug!("Yamux UDP 共享中继已结束");
    Ok(())
}

async fn spawn_yamux_udp_relay_flow(
    egress_state: Arc<EgressState>,
    flow_id: u64,
    address: Address,
    response_tx: tokio::sync::mpsc::Sender<QueuedUdpRelayResponse>,
    flow_done_tx: tokio::sync::mpsc::Sender<u64>,
    flow_permit: UdpRelayFlowPermit,
    flow_idle_timeout: Duration,
    channel_size: usize,
    connection_limiter: ConnectionLimiter,
    max_buffered_bytes: usize,
) -> Result<UdpRelayFlow> {
    let target_addr = relay_target_addr(&address)?;
    let socket = egress_state.connect_udp(&target_addr).await.map_err(|e| {
        ProxyError::Connection(format!("Failed to connect Yamux UDP relay target: {e}"))
    })?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<QueuedUdpRelayData>(channel_size);
    let response_address = address.clone();

    spawn_guarded("proxy yamux udp relay flow", async move {
        let _flow_permit = flow_permit;
        let mut buf = vec![0u8; 65535];
        let idle = tokio::time::sleep(flow_idle_timeout);
        tokio::pin!(idle);

        loop {
            tokio::select! {
                _ = &mut idle => break,
                maybe_data = rx.recv() => {
                    let Some(queued) = maybe_data else { break };
                    let data = queued.data;
                    match tokio::time::timeout(flow_idle_timeout, socket.send(&data)).await {
                        Ok(Ok(_)) => {
                            idle.as_mut().reset(tokio::time::Instant::now() + flow_idle_timeout);
                        }
                        Ok(Err(e)) => {
                            debug!("Yamux UDP relay flow {flow_id} 发送失败：{e}");
                            break;
                        }
                        Err(_) => {
                            debug!(
                                "Yamux UDP relay flow {flow_id} 发送超过 {} 秒，关闭该 flow",
                                flow_idle_timeout.as_secs()
                            );
                            break;
                        }
                    }
                }
                read = socket.recv(&mut buf) => {
                    match read {
                        Ok(n) => {
                            let Some(buffer_permit) = try_acquire_udp_relay_buffer(
                                &connection_limiter,
                                max_buffered_bytes,
                                flow_id,
                                n,
                                "下行",
                            ) else {
                                debug!("Yamux UDP relay flow {flow_id} 响应缓冲预算不足，关闭该 flow 以释放 socket");
                                break;
                            };
                            let response = QueuedUdpRelayResponse {
                                packet: UdpRelayPacket {
                                    flow_id,
                                    address: response_address.clone(),
                                    data: buf[..n].to_vec(),
                                },
                                _buffer_permit: buffer_permit,
                            };
                            match response_tx.try_send(response) {
                                Ok(()) => {
                                    idle.as_mut().reset(tokio::time::Instant::now() + flow_idle_timeout);
                                }
                                Err(TrySendError::Full(_)) => {
                                    debug!("Yamux UDP relay flow {flow_id} 响应队列已满，关闭该 flow 以释放 socket");
                                    break;
                                }
                                Err(TrySendError::Closed(_)) => break,
                            }
                        }
                        Err(e) => {
                            debug!("Yamux UDP relay flow {flow_id} 接收失败：{e}");
                            break;
                        }
                    }
                }
            }
        }
        drop(socket);
        let _ = flow_done_tx.send(flow_id).await;
        debug!("Yamux UDP relay flow {flow_id} 已结束");
    });

    Ok(UdpRelayFlow { tx })
}

async fn send_yamux_connect_success<W>(
    writer: &mut W,
    request_id: String,
    message: &str,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let response = ConnectResponse {
        request_id,
        success: true,
        message: message.to_string(),
    };
    write_yamux_connect_response(writer, &response).await?;
    Ok(())
}

async fn send_yamux_connect_error<W>(
    writer: &mut W,
    request_id: String,
    message: String,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let response = ConnectResponse {
        request_id,
        success: false,
        message,
    };
    write_yamux_connect_response(writer, &response).await?;
    Ok(())
}

fn target_addr_for_address(proxy_config: &ProxyConfig, address: &Address) -> Result<String> {
    match address {
        Address::ProxyDns { port } => proxy_dns_target_addr(proxy_config, *port),
        Address::TcpYamux | Address::UdpYamux | Address::UdpRelay => Err(ProxyError::Connection(
            "virtual target address cannot be used as a TCP target".to_string(),
        )),
        _ => Ok(format_target_addr(address)),
    }
}

fn proxy_dns_target_addr(proxy_config: &ProxyConfig, port: u16) -> Result<String> {
    // 显式配置优先，适合 Windows 或容器环境中系统 DNS 不可靠的情况。
    if let Some(addr) = proxy_config
        .dns_upstream_addr
        .as_deref()
        .map(str::trim)
        .filter(|addr| !addr.is_empty())
    {
        let target = endpoint_with_port(addr, port);
        debug!("DNS 请求使用 proxy 配置的上游 DNS：{target}");
        return Ok(target);
    }

    // 未配置时按当前系统 DNS 解析，保持默认行为贴近操作系统。
    let nameserver = system_dns_nameserver()?;
    let target = endpoint_with_port(&nameserver, port);
    debug!("DNS 请求使用 proxy 端默认上游 DNS：{target}");
    Ok(target)
}

fn format_target_addr(address: &Address) -> String {
    // 协议地址统一转成 host:port，供 Tokio lookup_host/connect 使用。
    match address {
        Address::Domain { host, port } => format!("{}:{}", host, port),
        Address::Ipv4 { addr, port } => {
            format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port)
        }
        Address::Ipv6 { addr, port } => {
            format!(
                "[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]:{}",
                u16::from_be_bytes([addr[0], addr[1]]),
                u16::from_be_bytes([addr[2], addr[3]]),
                u16::from_be_bytes([addr[4], addr[5]]),
                u16::from_be_bytes([addr[6], addr[7]]),
                u16::from_be_bytes([addr[8], addr[9]]),
                u16::from_be_bytes([addr[10], addr[11]]),
                u16::from_be_bytes([addr[12], addr[13]]),
                u16::from_be_bytes([addr[14], addr[15]]),
                port
            )
        }
        Address::ProxyDns { port } => format!("proxy-dns:{port}"),
        Address::TcpYamux => "tcp-yamux".to_string(),
        Address::UdpYamux => "udp-yamux".to_string(),
        Address::UdpRelay => "udp-relay".to_string(),
    }
}

fn relay_target_addr(address: &Address) -> Result<String> {
    match address {
        Address::Domain { .. } | Address::Ipv4 { .. } | Address::Ipv6 { .. } => {
            Ok(format_target_addr(address))
        }
        Address::ProxyDns { .. } | Address::TcpYamux | Address::UdpYamux | Address::UdpRelay => {
            Err(ProxyError::Connection(
                "UDP relay packet contains virtual target address".to_string(),
            ))
        }
    }
}

#[cfg(not(windows))]
fn system_dns_nameserver() -> Result<String> {
    // Unix 系统优先读取 resolv.conf 中第一个 nameserver。
    let resolv_conf = fs::read_to_string("/etc/resolv.conf").map_err(|e| {
        ProxyError::Configuration(format!("读取系统 DNS 配置 /etc/resolv.conf 失败：{e}"))
    })?;
    resolv_conf
        .lines()
        .find_map(parse_resolv_nameserver)
        .map(str::to_owned)
        .ok_or_else(|| {
            ProxyError::Configuration("系统 DNS 配置中没有可用的 nameserver".to_string())
        })
}

#[cfg(windows)]
fn system_dns_nameserver() -> Result<String> {
    const INITIAL_BUFFER_SIZE: u32 = 15_000;
    const MAX_ATTEMPTS: usize = 3;

    // Windows 下优先使用默认路由所在网卡的 DNS，避免误选 TUN/虚拟网卡 DNS。
    let preferred_if_indices = windows_default_route_if_indices();
    let mut buffer_size = INITIAL_BUFFER_SIZE;

    for _ in 0..MAX_ATTEMPTS {
        // GetAdaptersAddresses 会在缓冲区不足时回填所需大小，最多重试几次。
        let mut buffer = vec![0u8; buffer_size as usize];
        let adapters = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let status = unsafe {
            GetAdaptersAddresses(
                0,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                ptr::null(),
                adapters,
                &mut buffer_size,
            )
        };

        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }

        if status != ERROR_SUCCESS {
            return Err(ProxyError::Configuration(format!(
                "读取 Windows 系统 DNS 配置失败：GetAdaptersAddresses 返回 {status}"
            )));
        }

        // 先找默认路由网卡 DNS，找不到再降级到其他可解析网卡。
        if let Some(ip) = unsafe { find_windows_dns_server(adapters, &preferred_if_indices) } {
            return Ok(ip.to_string());
        }

        return Err(ProxyError::Configuration(
            "Windows 系统 DNS 配置中没有可用的 nameserver；可在 proxy.toml 中设置 dns_upstream_addr".to_string(),
        ));
    }

    Err(ProxyError::Configuration(
        "读取 Windows 系统 DNS 配置失败：网卡信息缓冲区持续不足".to_string(),
    ))
}

#[cfg(windows)]
fn windows_default_route_if_indices() -> Vec<u32> {
    // 读取当前默认路由的 if_index，用来给 DNS 网卡选择排序。
    let Ok(mut route_manager) = route_manager::RouteManager::new() else {
        return Vec::new();
    };
    let Ok(routes) = route_manager.list() else {
        return Vec::new();
    };

    let mut indices = Vec::new();
    for route in routes {
        // 只关心 IPv4/IPv6 默认路由。
        if route.prefix() != 0 {
            continue;
        }

        let is_default = match route.destination() {
            IpAddr::V4(addr) => addr.is_unspecified(),
            IpAddr::V6(addr) => addr.is_unspecified(),
        };
        if !is_default {
            continue;
        }

        if let Some(if_index) = route.if_index()
            && !indices.contains(&if_index)
        {
            indices.push(if_index);
        }
    }

    indices
}

#[cfg(windows)]
unsafe fn find_windows_dns_server(
    adapters: *mut IP_ADAPTER_ADDRESSES_LH,
    preferred_if_indices: &[u32],
) -> Option<IpAddr> {
    // 第一轮只查默认路由网卡，第二轮放宽到其他可用物理网卡。
    for preferred_only in [true, false] {
        let mut adapter = adapters;
        while !adapter.is_null() {
            let adapter_ref = unsafe { &*adapter };
            let is_preferred = windows_adapter_matches_if_index(adapter_ref, preferred_if_indices);

            if windows_adapter_can_resolve(adapter_ref)
                && (!preferred_only || is_preferred || preferred_if_indices.is_empty())
            {
                // 同一网卡可能配置多个 DNS，返回第一个可用地址。
                let mut dns = adapter_ref.FirstDnsServerAddress;
                while !dns.is_null() {
                    let dns_ref = unsafe { &*dns };
                    if let Some(ip) = unsafe { socket_address_to_ip(dns_ref.Address) }
                        && dns_ip_is_usable(ip)
                    {
                        return Some(ip);
                    }
                    dns = dns_ref.Next;
                }
            }

            adapter = adapter_ref.Next;
        }
    }

    None
}

#[cfg(windows)]
fn windows_adapter_can_resolve(adapter: &IP_ADAPTER_ADDRESSES_LH) -> bool {
    // 排除未启用、回环和隧道网卡，减少选到 TUN 的概率。
    adapter.OperStatus == IfOperStatusUp
        && adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK
        && adapter.IfType != IF_TYPE_TUNNEL
}

#[cfg(windows)]
fn windows_adapter_matches_if_index(
    adapter: &IP_ADAPTER_ADDRESSES_LH,
    preferred_if_indices: &[u32],
) -> bool {
    // IPv4 IfIndex 和 IPv6 Ipv6IfIndex 都可能对应默认路由。
    if preferred_if_indices.is_empty() {
        return false;
    }

    let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
    preferred_if_indices.contains(&if_index)
        || (adapter.Ipv6IfIndex != 0 && preferred_if_indices.contains(&adapter.Ipv6IfIndex))
}

#[cfg(windows)]
fn dns_ip_is_usable(ip: IpAddr) -> bool {
    // DNS 上游必须是可路由的单播地址。
    match ip {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast(),
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
        }
    }
}

#[cfg(windows)]
unsafe fn socket_address_to_ip(address: SOCKET_ADDRESS) -> Option<IpAddr> {
    // Windows API 返回原始 sockaddr 指针，这里按地址族转换成 Rust IpAddr。
    if address.lpSockaddr.is_null() {
        return None;
    }

    let family = unsafe { (*address.lpSockaddr).sa_family };
    match family {
        AF_INET if address.iSockaddrLength as usize >= std::mem::size_of::<SOCKADDR_IN>() => {
            let sockaddr = unsafe { &*(address.lpSockaddr.cast::<SOCKADDR_IN>()) };
            let octets = unsafe { sockaddr.sin_addr.S_un.S_un_b };
            Some(IpAddr::V4(Ipv4Addr::new(
                octets.s_b1,
                octets.s_b2,
                octets.s_b3,
                octets.s_b4,
            )))
        }
        AF_INET6 if address.iSockaddrLength as usize >= std::mem::size_of::<SOCKADDR_IN6>() => {
            let sockaddr = unsafe { &*(address.lpSockaddr.cast::<SOCKADDR_IN6>()) };
            let octets = unsafe { sockaddr.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(not(windows))]
fn parse_resolv_nameserver(line: &str) -> Option<&str> {
    // 忽略注释和空白，只接受 nameserver 行的第二列。
    let line = line.split(['#', ';']).next()?.trim();
    let mut parts = line.split_whitespace();
    if parts.next()? != "nameserver" {
        return None;
    }

    parts.next()
}

fn endpoint_with_port(value: &str, default_port: u16) -> String {
    // 配置值可只写 IP/域名，缺省端口由请求的 DNS 端口补齐。
    let value = value.trim();
    if has_explicit_port(value) {
        return value.to_string();
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return SocketAddr::new(ip, default_port).to_string();
    }

    if value.contains(':') {
        format!("[{value}]:{default_port}")
    } else {
        format!("{value}:{default_port}")
    }
}

fn has_explicit_port(value: &str) -> bool {
    // 支持 [IPv6]:port 和 host:port；裸 IPv6 不视为带端口。
    if let Some(rest) = value.strip_prefix('[')
        && let Some((_, port)) = rest.rsplit_once("]:")
    {
        return port.parse::<u16>().is_ok();
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        return !host.contains(':') && port.parse::<u16>().is_ok();
    }

    false
}
