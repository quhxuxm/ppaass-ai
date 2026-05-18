mod agent_io;
mod egress;
mod response_sink;
mod upstream;

pub use agent_io::AgentIo;
pub use response_sink::BytesToProxyResponseSink;
// UpstreamConnection 在 ServerConnection 定义之后于文件末尾导出

use crate::bandwidth::BandwidthMonitor;
use crate::config::{ProxyConfig, UserConfig};
use crate::connection::upstream::UpstreamConnection;
use crate::error::{ProxyError, Result};
use bytes::Bytes;
use futures::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use protocol::{
    Address, AuthRequest, AuthResponse, CipherState, CompressionMode, ConnectRequest,
    ConnectResponse, ProxyCodec, ProxyRequest, ProxyResponse, TransportProtocol,
    crypto::{AesGcmCipher, RsaKeyPair},
};
#[cfg(not(windows))]
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
#[cfg(windows)]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use std::ptr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::codec::Framed;
use tokio_util::io::{SinkWriter, StreamReader};
use tracing::{debug, error, info, instrument, trace};
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

pub struct ServerConnection {
    writer: FramedWriter,
    reader: FramedReader,
    user_config: Option<UserConfig>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    cipher_state: Arc<CipherState>,
    pending_auth_request: Option<AuthRequest>,
    proxy_config: Arc<ProxyConfig>,
}

impl ServerConnection {
    pub fn new(
        stream: TcpStream,
        bandwidth_monitor: Arc<BandwidthMonitor>,
        compression_mode: CompressionMode,
        proxy_config: Arc<ProxyConfig>,
    ) -> Self {
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
        }
    }

    async fn read_request(&mut self) -> Result<Option<ProxyRequest>> {
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
        info!("正在认证用户连接：{}", user_config.username);

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

        info!("认证成功");
        Ok(())
    }

    async fn send_response(&mut self, response: ProxyResponse) -> Result<()> {
        self.writer
            .send(response)
            .await
            .map_err(|e| ProxyError::Connection(format!("Failed to send response: {}", e)))?;
        Ok(())
    }

    pub async fn handle_request(&mut self) -> Result<()> {
        // 只循环处理初始请求（认证、连接）。
        // 一旦连接成功，就移交给中继并返回。
        loop {
            match self.read_request().await? {
                Some(ProxyRequest::Connect(connect_request)) => {
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
        info!("连接请求：{:?}", connect_request.address);

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
        match address {
            Address::ProxyDns { port } => self.proxy_dns_target_addr(*port),
            _ => Ok(format_target_addr(address)),
        }
    }

    fn proxy_dns_target_addr(&self, port: u16) -> Result<String> {
        if let Some(addr) = self
            .proxy_config
            .dns_upstream_addr
            .as_deref()
            .map(str::trim)
            .filter(|addr| !addr.is_empty())
        {
            let target = endpoint_with_port(addr, port);
            info!("DNS 请求使用 proxy 配置的上游 DNS：{target}");
            return Ok(target);
        }

        let nameserver = system_dns_nameserver()?;
        let target = endpoint_with_port(&nameserver, port);
        info!("DNS 请求使用 proxy 端默认上游 DNS：{target}");
        Ok(target)
    }

    async fn handle_upstream_connect(&mut self, connect_request: ConnectRequest) -> Result<()> {
        info!("正在将请求转发到上游代理");

        match UpstreamConnection::connect(
            &self.proxy_config,
            connect_request.address.clone(),
            connect_request.transport,
        )
        .await
        {
            Ok(upstream_conn) => {
                info!("已连接到上游代理");
                self.send_connect_success(
                    connect_request.request_id.clone(),
                    "Connected through upstream",
                )
                .await?;

                let mut stream = upstream_conn.into_stream();
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
        match egress::connect_tcp(target_addr, self.proxy_config.outbound_interface.as_deref())
            .await
        {
            Ok(mut target_stream) => {
                info!(
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
            Err(e) => {
                error!("连接目标失败（TCP）：{}", e);
                self.send_connect_error(
                    connect_request.request_id,
                    format!("Failed to connect: {}", e),
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn handle_udp_connect(
        &mut self,
        connect_request: ConnectRequest,
        target_addr: &str,
    ) -> Result<()> {
        debug!("正在处理 UDP 连接请求：{connect_request:?}");

        match egress::connect_udp(target_addr, self.proxy_config.outbound_interface.as_deref())
            .await
        {
            Ok(socket) => {
                info!(
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
                error!("连接目标失败（UDP）：{}", e);
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
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();
        let stream_id_filter = stream_id.clone();

        // 使用自定义 Sink 实现
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

        let agent_io = AgentIo { reader, writer };

        let udp_socket = Arc::new(udp_socket);
        let udp_recv = udp_socket.clone();
        let udp_send = udp_socket.clone();

        let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);

        let agent_to_udp = async {
            let mut buf = [0u8; 65535];
            loop {
                match agent_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = &buf[..n];
                        trace!(
                            "从 agent 收到发往目标的 UDP 数据：{:?}\n{}",
                            udp_socket.peer_addr(),
                            pretty_hex::pretty_hex(&data)
                        );
                        if let Err(e) = udp_send.send(data).await {
                            debug!("UDP 发送错误：{}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("读取 agent 数据错误：{}", e);
                        break;
                    }
                }
            }
        };

        let udp_to_agent = async {
            let mut buf = [0u8; 65535];
            loop {
                match udp_recv.recv(&mut buf).await {
                    Ok(n) => {
                        let data = &buf[..n];
                        trace!(
                            "从目标收到发往 agent 的 UDP 数据：{:?}\n{}",
                            udp_socket.peer_addr(),
                            pretty_hex::pretty_hex(&data)
                        );
                        if let Err(e) = agent_writer.write_all(data).await {
                            debug!("写入 agent 数据错误：{}", e);
                            break;
                        }
                        if let Err(e) = agent_writer.flush().await {
                            debug!("刷新 agent 写入缓冲错误：{}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("UDP 接收错误：{}", e);
                        break;
                    }
                }
            }
        };

        tokio::select! {
            _ = agent_to_udp => {},
            _ = udp_to_agent => {}
        }

        debug!("UDP 中继已结束");
        Ok(())
    }

    async fn relay<S>(&mut self, stream_id: String, target_stream: &mut S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
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

        let mut agent_io = AgentIo { reader, writer };

        match tokio::io::copy_bidirectional(target_stream, &mut agent_io).await {
            Ok((up, down)) => debug!("中继已结束：上行 {}，下行 {}", up, down),
            Err(e) => debug!("中继错误：{}", e),
        }

        Ok(())
    }

    async fn send_connect_error(&mut self, request_id: String, message: String) -> Result<()> {
        let connect_response = ConnectResponse {
            request_id,
            success: false,
            message,
        };

        self.send_response(ProxyResponse::Connect(connect_response))
            .await
    }

    async fn send_connect_success(&mut self, request_id: String, message: &str) -> Result<()> {
        let connect_response = ConnectResponse {
            request_id,
            success: true,
            message: message.to_string(),
        };

        self.send_response(ProxyResponse::Connect(connect_response))
            .await
    }
}

fn format_target_addr(address: &Address) -> String {
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
    }
}

#[cfg(not(windows))]
fn system_dns_nameserver() -> Result<String> {
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

    let preferred_if_indices = windows_default_route_if_indices();
    let mut buffer_size = INITIAL_BUFFER_SIZE;

    for _ in 0..MAX_ATTEMPTS {
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
    let Ok(mut route_manager) = route_manager::RouteManager::new() else {
        return Vec::new();
    };
    let Ok(routes) = route_manager.list() else {
        return Vec::new();
    };

    let mut indices = Vec::new();
    for route in routes {
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
    for preferred_only in [true, false] {
        let mut adapter = adapters;
        while !adapter.is_null() {
            let adapter_ref = unsafe { &*adapter };
            let is_preferred = windows_adapter_matches_if_index(adapter_ref, preferred_if_indices);

            if windows_adapter_can_resolve(adapter_ref)
                && (!preferred_only || is_preferred || preferred_if_indices.is_empty())
            {
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
    adapter.OperStatus == IfOperStatusUp
        && adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK
        && adapter.IfType != IF_TYPE_TUNNEL
}

#[cfg(windows)]
fn windows_adapter_matches_if_index(
    adapter: &IP_ADAPTER_ADDRESSES_LH,
    preferred_if_indices: &[u32],
) -> bool {
    if preferred_if_indices.is_empty() {
        return false;
    }

    let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
    preferred_if_indices.contains(&if_index)
        || (adapter.Ipv6IfIndex != 0 && preferred_if_indices.contains(&adapter.Ipv6IfIndex))
}

#[cfg(windows)]
fn dns_ip_is_usable(ip: IpAddr) -> bool {
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
    let line = line.split(['#', ';']).next()?.trim();
    let mut parts = line.split_whitespace();
    if parts.next()? != "nameserver" {
        return None;
    }

    parts.next()
}

fn endpoint_with_port(value: &str, default_port: u16) -> String {
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
