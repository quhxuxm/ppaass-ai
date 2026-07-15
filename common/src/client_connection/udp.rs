//! PPAASS native encrypted UDP client sessions.
//!
//! One connection owns one connected UDP socket and one authenticated security
//! context. Logical UDP channels are multiplexed by `flow_id`; each call to
//! `poll_write` remains exactly one UDP payload and is never retransmitted.

use protocol::udp_transport::{
    UDP_MAX_DATAGRAM_SIZE, UdpAuthInit, UdpSessionCodec, UdpSessionMessage, UdpSessionRole,
    decode_auth_ok, decode_session_secret, encode_auth_init, udp_auth_proof_digest,
};
use protocol::{Address, RsaKeyPair, TransportProtocol};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::PollSender;
use tracing::{debug, info, trace, warn};

use super::config::ClientConnectionConfig;
use super::socket_bind::bind_socket_to_interface;

const SESSION_COMMAND_CAPACITY: usize = 1024;
const STREAM_INBOUND_CAPACITY: usize = 256;
const AUTH_INITIAL_RETRY: Duration = Duration::from_millis(200);
const CONTROL_MAX_RETRY: Duration = Duration::from_secs(2);
const SESSION_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct UdpClientConnection {
    inner: Arc<UdpClientConnectionInner>,
}

struct UdpClientConnectionInner {
    command_tx: mpsc::Sender<ClientCommand>,
    closed: Arc<AtomicBool>,
    next_flow_id: AtomicU64,
    timeout: Duration,
}

enum ClientCommand {
    Open {
        flow_id: u64,
        address: Address,
        inbound_tx: mpsc::Sender<Vec<u8>>,
        response_tx: oneshot::Sender<std::result::Result<(), String>>,
    },
    ResendConnect {
        flow_id: u64,
        address: Address,
    },
    CancelOpen {
        flow_id: u64,
    },
    Data {
        flow_id: u64,
        data: Vec<u8>,
    },
    Close {
        flow_id: u64,
    },
}

impl UdpClientConnection {
    pub async fn connect<C>(config: &C) -> io::Result<Self>
    where
        C: ClientConnectionConfig,
    {
        let timeout = config.timeout_duration();
        let socket = connect_udp_socket(config).await?;
        let (session_id, codec) = authenticate_udp_session(&socket, config, timeout).await?;
        let (command_tx, command_rx) = mpsc::channel(SESSION_COMMAND_CAPACITY);
        let closed = Arc::new(AtomicBool::new(false));
        let driver_closed = closed.clone();

        tokio::spawn(async move {
            if let Err(error) = run_session_driver(socket, codec, command_rx).await {
                debug!(session = %hex::encode(session_id), "原生 UDP 会话结束：{error}");
            }
            driver_closed.store(true, Ordering::Release);
        });

        let mut first_flow_id = rand::random::<u64>();
        if first_flow_id == 0 {
            first_flow_id = 1;
        }
        info!(session = %hex::encode(session_id), "已建立原生加密 UDP proxy 会话");
        Ok(Self {
            inner: Arc::new(UdpClientConnectionInner {
                command_tx,
                closed,
                next_flow_id: AtomicU64::new(first_flow_id),
                timeout,
            }),
        })
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire) || self.inner.command_tx.is_closed()
    }

    pub async fn connect_to_target(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> io::Result<(UdpClientStream, String)> {
        if transport != TransportProtocol::Udp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "原生 UDP 会话只能承载 UDP 目标",
            ));
        }
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "原生 UDP 会话已关闭",
            ));
        }

        let flow_id = self.inner.next_flow_id.fetch_add(1, Ordering::AcqRel);
        if flow_id == u64::MAX {
            self.inner.closed.store(true, Ordering::Release);
            return Err(io::Error::other("原生 UDP channel ID 已耗尽"));
        }
        let (inbound_tx, inbound_rx) = mpsc::channel(STREAM_INBOUND_CAPACITY);
        let (response_tx, mut response_rx) = oneshot::channel();
        self.inner
            .command_tx
            .send(ClientCommand::Open {
                flow_id,
                address: address.clone(),
                inbound_tx,
                response_tx,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "原生 UDP 会话已关闭"))?;

        let deadline = Instant::now() + self.inner.timeout;
        let mut retry_delay = AUTH_INITIAL_RETRY;
        let result = loop {
            let now = Instant::now();
            if now >= deadline {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "UDP CONNECT 响应超时",
                ));
            }
            let wait = retry_delay.min(deadline.saturating_duration_since(now));
            match tokio::time::timeout(wait, &mut response_rx).await {
                Ok(Ok(Ok(()))) => break Ok(()),
                Ok(Ok(Err(message))) => {
                    break Err(io::Error::new(io::ErrorKind::ConnectionRefused, message));
                }
                Ok(Err(_)) => {
                    break Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "原生 UDP 会话在 CONNECT 期间关闭",
                    ));
                }
                Err(_) if Instant::now() < deadline => {
                    self.inner
                        .command_tx
                        .send(ClientCommand::ResendConnect {
                            flow_id,
                            address: address.clone(),
                        })
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::NotConnected, "原生 UDP 会话已关闭")
                        })?;
                    retry_delay = (retry_delay * 2).min(CONTROL_MAX_RETRY);
                }
                Err(_) => {
                    break Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "UDP CONNECT 响应超时",
                    ));
                }
            }
        };

        if let Err(error) = result {
            let _ = self
                .inner
                .command_tx
                .send(ClientCommand::CancelOpen { flow_id })
                .await;
            return Err(error);
        }

        let stream_id = flow_id.to_string();
        Ok((
            UdpClientStream {
                flow_id,
                stream_id: stream_id.clone(),
                command_tx: PollSender::new(self.inner.command_tx.clone()),
                inbound_rx,
                read_buf: Vec::new(),
                read_pos: 0,
                close_sent: false,
            },
            stream_id,
        ))
    }
}

async fn connect_udp_socket<C>(config: &C) -> io::Result<UdpSocket>
where
    C: ClientConnectionConfig,
{
    let remote_name = config.remote_addr();
    let timeout = config.timeout_duration();
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(&remote_name).await?.collect();
    let bind_addr = config.bind_addr();
    let mut last_error = None;

    for remote in resolved {
        if bind_addr.is_some_and(|bind| bind.is_ipv4() != remote.is_ipv4()) {
            continue;
        }
        match connect_udp_socket_to(config, remote, bind_addr, timeout).await {
            Ok(socket) => return Ok(socket),
            Err(error) => {
                warn!(%remote, "建立原生 UDP proxy socket 失败：{error}");
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("proxy 地址 {remote_name} 没有可用的 UDP 端点"),
        )
    }))
}

async fn connect_udp_socket_to<C>(
    config: &C,
    remote: SocketAddr,
    configured_bind: Option<SocketAddr>,
    timeout: Duration,
) -> io::Result<UdpSocket>
where
    C: ClientConnectionConfig,
{
    let socket = Socket::new(
        Domain::for_address(remote),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if let Some(size) = config.udp_socket_buffer_size() {
        if let Err(error) = socket.set_recv_buffer_size(size) {
            debug!(%remote, "设置原生 UDP SO_RCVBUF 失败：{error}");
        }
        if let Err(error) = socket.set_send_buffer_size(size) {
            debug!(%remote, "设置原生 UDP SO_SNDBUF 失败：{error}");
        }
    }

    // Android VpnService.protect() must happen before bind/connect, otherwise
    // the proxy socket can be routed recursively back into the TUN.
    config.protect_udp_socket(&socket, remote)?;
    bind_socket_to_interface(&socket, config.bind_interface().as_ref(), remote)?;
    let bind = configured_bind.unwrap_or_else(|| {
        SocketAddr::new(
            if remote.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        )
    });
    socket.bind(&SockAddr::from(bind))?;
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket.into())?;
    tokio::time::timeout(timeout, socket.connect(remote))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "连接原生 UDP proxy 超时"))??;
    Ok(socket)
}

async fn authenticate_udp_session<C>(
    socket: &UdpSocket,
    config: &C,
    timeout: Duration,
) -> io::Result<([u8; 16], UdpSessionCodec)>
where
    C: ClientConnectionConfig,
{
    let session_id = random_bytes();
    let client_nonce = random_bytes();
    let username = config.username();
    let timestamp = crate::current_timestamp();
    let private_key_pem = config
        .private_key_pem()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let rsa = RsaKeyPair::from_private_key_pem(&private_key_pem)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let digest = udp_auth_proof_digest(&session_id, &username, timestamp, &client_nonce);
    let proof = rsa
        .sign_pss_sha256(&digest)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let auth = UdpAuthInit {
        username,
        timestamp,
        client_nonce,
        proof,
    };
    let request = encode_auth_init(session_id, &auth).map_err(udp_protocol_error)?;
    let deadline = Instant::now() + timeout;
    let mut retry_delay = AUTH_INITIAL_RETRY;
    let mut buffer = vec![0_u8; UDP_MAX_DATAGRAM_SIZE + 1];

    loop {
        socket.send(&request).await?;
        let attempt_deadline = (Instant::now() + retry_delay).min(deadline);
        loop {
            let remaining = attempt_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let received = tokio::time::timeout(remaining, socket.recv(&mut buffer)).await;
            let Ok(Ok(size)) = received else { break };
            if size > UDP_MAX_DATAGRAM_SIZE {
                continue;
            }
            let auth_ok = match decode_auth_ok(&buffer[..size]) {
                Ok((header, auth_ok)) if header.session_id == session_id => auth_ok,
                Ok(_) | Err(_) => continue,
            };
            let secret_bytes = match rsa.decrypt_oaep_sha256(&auth_ok.encrypted_session_secret) {
                Ok(secret) => secret,
                Err(_) => continue,
            };
            let secret = match decode_session_secret(&secret_bytes) {
                Ok(secret) => secret,
                Err(_) => continue,
            };
            if secret
                .validate_handshake_context(&session_id, &client_nonce)
                .is_err()
            {
                continue;
            }
            let codec = UdpSessionCodec::new(
                UdpSessionRole::Agent,
                session_id,
                secret.master_key,
                client_nonce,
                secret.server_nonce,
            )
            .map_err(udp_protocol_error)?;
            return Ok((session_id, codec));
        }

        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "原生 UDP 认证响应超时",
            ));
        }
        retry_delay = (retry_delay * 2).min(CONTROL_MAX_RETRY);
    }
}

async fn run_session_driver(
    socket: UdpSocket,
    mut codec: UdpSessionCodec,
    mut command_rx: mpsc::Receiver<ClientCommand>,
) -> io::Result<()> {
    let mut streams = HashMap::<u64, mpsc::Sender<Vec<u8>>>::new();
    let mut pending = HashMap::<u64, oneshot::Sender<std::result::Result<(), String>>>::new();
    let mut receive_buffer = vec![0_u8; UDP_MAX_DATAGRAM_SIZE + 1];
    let mut keepalive = tokio::time::interval(SESSION_KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // interval's first tick is immediate; consume it so authentication is not
    // followed by an unnecessary ping burst.
    keepalive.tick().await;
    let mut ping_token = 0_u64;

    loop {
        tokio::select! {
            command = command_rx.recv() => {
                let Some(command) = command else { return Ok(()) };
                let message = match command {
                    ClientCommand::Open { flow_id, address, inbound_tx, response_tx } => {
                        streams.insert(flow_id, inbound_tx);
                        pending.insert(flow_id, response_tx);
                        Some(UdpSessionMessage::Connect { flow_id, address })
                    }
                    ClientCommand::ResendConnect { flow_id, address } => {
                        pending.contains_key(&flow_id).then_some(UdpSessionMessage::Connect { flow_id, address })
                    }
                    ClientCommand::CancelOpen { flow_id } => {
                        pending.remove(&flow_id);
                        streams.remove(&flow_id);
                        Some(UdpSessionMessage::Close { flow_id, reason: Some("connect cancelled".to_string()) })
                    }
                    ClientCommand::Data { flow_id, data } => {
                        streams.contains_key(&flow_id).then_some(UdpSessionMessage::Data { flow_id, data })
                    }
                    ClientCommand::Close { flow_id } => {
                        pending.remove(&flow_id);
                        streams.remove(&flow_id);
                        Some(UdpSessionMessage::Close { flow_id, reason: None })
                    }
                };
                if let Some(message) = message {
                    send_message(&socket, &mut codec, &message).await?;
                }
            }
            received = socket.recv(&mut receive_buffer) => {
                let size = received?;
                if size > UDP_MAX_DATAGRAM_SIZE {
                    continue;
                }
                let message = match codec.decode_datagram(&receive_buffer[..size]) {
                    Ok(Some(message)) => message,
                    Ok(None) => continue,
                    Err(error) => {
                        trace!("丢弃无效原生 UDP 数据报：{error}");
                        continue;
                    }
                };
                match message {
                    UdpSessionMessage::ConnectResponse { flow_id, success, error } => {
                        if let Some(response) = pending.remove(&flow_id) {
                            if success {
                                let _ = response.send(Ok(()));
                            } else {
                                streams.remove(&flow_id);
                                let _ = response.send(Err(error.unwrap_or_else(|| "UDP CONNECT failed".to_string())));
                            }
                        }
                    }
                    UdpSessionMessage::Data { flow_id, data } => {
                        if let Some(stream) = streams.get(&flow_id) {
                            match stream.try_send(data) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    trace!(flow_id, "UDP channel 接收队列已满，丢弃一个数据报");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    streams.remove(&flow_id);
                                }
                            }
                        }
                    }
                    UdpSessionMessage::Close { flow_id, reason } => {
                        streams.remove(&flow_id);
                        if let Some(response) = pending.remove(&flow_id) {
                            let _ = response.send(Err(reason.unwrap_or_else(|| "proxy closed UDP channel".to_string())));
                        }
                    }
                    UdpSessionMessage::Ping { token } => {
                        send_message(&socket, &mut codec, &UdpSessionMessage::Pong { token }).await?;
                    }
                    UdpSessionMessage::Pong { .. } => {}
                    UdpSessionMessage::Connect { .. } => {
                        trace!("忽略 proxy 发来的意外 UDP CONNECT");
                    }
                }
            }
            _ = keepalive.tick() => {
                send_message(&socket, &mut codec, &UdpSessionMessage::Ping { token: ping_token }).await?;
                ping_token = ping_token.wrapping_add(1);
            }
        }
    }
}

async fn send_message(
    socket: &UdpSocket,
    codec: &mut UdpSessionCodec,
    message: &UdpSessionMessage,
) -> io::Result<()> {
    let datagrams = codec.encode_message(message).map_err(udp_protocol_error)?;
    for datagram in datagrams {
        let sent = socket.send(&datagram).await?;
        if sent != datagram.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "原生 UDP 数据报未完整发送",
            ));
        }
    }
    Ok(())
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    rand::fill(&mut bytes);
    bytes
}

fn udp_protocol_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub struct UdpClientStream {
    flow_id: u64,
    stream_id: String,
    command_tx: PollSender<ClientCommand>,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    close_sent: bool,
}

impl UdpClientStream {
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
}

impl AsyncRead for UdpClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.read_pos < self.read_buf.len() {
            let datagram_len = self.read_buf.len() - self.read_pos;
            if buf.remaining() < datagram_len {
                return Poll::Ready(Err(short_datagram_buffer_error(
                    buf.remaining(),
                    datagram_len,
                )));
            }
            buf.put_slice(&self.read_buf[self.read_pos..]);
            self.read_pos = self.read_buf.len();
            return Poll::Ready(Ok(()));
        }
        self.read_buf.clear();
        self.read_pos = 0;

        loop {
            match Pin::new(&mut self.inbound_rx).poll_recv(cx) {
                Poll::Ready(Some(data)) if data.is_empty() => continue,
                Poll::Ready(Some(data)) => {
                    self.read_buf = data;
                    if buf.remaining() < self.read_buf.len() {
                        return Poll::Ready(Err(short_datagram_buffer_error(
                            buf.remaining(),
                            self.read_buf.len(),
                        )));
                    }
                    buf.put_slice(&self.read_buf);
                    self.read_pos = self.read_buf.len();
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn short_datagram_buffer_error(available: usize, required: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "UDP read buffer is too small for one datagram: available={available}, required={required}"
        ),
    )
}

impl AsyncWrite for UdpClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.command_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let flow_id = self.flow_id;
                self.command_tx
                    .send_item(ClientCommand::Data {
                        flow_id,
                        data: buf.to_vec(),
                    })
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::NotConnected, "原生 UDP 会话已关闭")
                    })?;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "原生 UDP 会话已关闭",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // UDP has no userspace flush boundary. A successful poll_write means the
        // complete datagram was accepted by the bounded session queue.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.close_sent {
            return Poll::Ready(Ok(()));
        }
        match self.command_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let flow_id = self.flow_id;
                self.command_tx
                    .send_item(ClientCommand::Close { flow_id })
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::NotConnected, "原生 UDP 会话已关闭")
                    })?;
                self.close_sent = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                self.close_sent = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for UdpClientStream {
    fn drop(&mut self) {
        if self.close_sent {
            return;
        }
        if let Some(sender) = self.command_tx.get_ref() {
            let _ = sender.try_send(ClientCommand::Close {
                flow_id: self.flow_id,
            });
        }
    }
}

impl Unpin for UdpClientStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn stream_rejects_short_read_buffer_without_splitting_datagram() {
        let (command_tx, _command_rx) = mpsc::channel(1);
        let (inbound_tx, inbound_rx) = mpsc::channel(1);
        let mut stream = UdpClientStream {
            flow_id: 1,
            stream_id: "test-stream".to_string(),
            command_tx: PollSender::new(command_tx),
            inbound_rx,
            read_buf: Vec::new(),
            read_pos: 0,
            close_sent: false,
        };
        inbound_tx.send(vec![1, 2, 3, 4]).await.unwrap();

        let mut short = [0u8; 3];
        let error = stream.read(&mut short).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(short, [0; 3]);

        let mut exact = [0u8; 4];
        assert_eq!(stream.read(&mut exact).await.unwrap(), 4);
        assert_eq!(exact, [1, 2, 3, 4]);
    }
}
