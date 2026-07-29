//! PPAASS native encrypted UDP client sessions.
//!
//! One connection owns one connected UDP socket and one authenticated security
//! context. Logical UDP channels are multiplexed by `flow_id`; each call to
//! `poll_write` remains exactly one UDP payload and is never retransmitted.

use protocol::crypto::verify_pss_sha256;
use protocol::udp_transport::{
    UDP_MAX_DATAGRAM_SIZE, UDP_OAEP_LABEL, UdpAuthInit, UdpSessionCodec, UdpSessionMessage,
    UdpSessionRole, decode_auth_ok, decode_session_secret, encode_auth_init,
    udp_auth_ok_signature_transcript, udp_auth_proof_digest,
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
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::PollSender;
use tracing::{debug, info, trace, warn};

use super::config::ClientConnectionConfig;
use super::socket_bind::bind_socket_to_interface;

mod session;
mod stream;

use session::{authenticate_udp_session, connect_udp_socket};
pub use stream::UdpClientStream;

const SESSION_COMMAND_CAPACITY: usize = 1024;
const STREAM_INBOUND_CAPACITY: usize = 256;
const AUTH_INITIAL_RETRY: Duration = Duration::from_millis(200);
const CONTROL_MAX_RETRY: Duration = Duration::from_secs(2);
const SESSION_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const MIN_SESSION_HEALTH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct UdpClientConnection {
    inner: Arc<UdpClientConnectionInner>,
}

struct UdpClientConnectionInner {
    command_tx: mpsc::Sender<ClientCommand>,
    closed: Arc<AtomicBool>,
    timed_out: Arc<AtomicBool>,
    next_flow_id: AtomicU64,
}

enum ClientCommand {
    Register {
        flow_id: u64,
        inbound_tx: mpsc::Sender<Vec<u8>>,
    },
    OpenData {
        flow_id: u64,
        address: Address,
        data: Vec<u8>,
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
        let timed_out = Arc::new(AtomicBool::new(false));
        let driver_timed_out = timed_out.clone();

        tokio::spawn(async move {
            if let Err(error) = run_session_driver(socket, codec, command_rx, timeout).await {
                if error.kind() == io::ErrorKind::TimedOut {
                    driver_timed_out.store(true, Ordering::Release);
                }
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
                timed_out,
                next_flow_id: AtomicU64::new(first_flow_id),
            }),
        })
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire) || self.inner.command_tx.is_closed()
    }

    /// Returns true when this encrypted UDP transport was closed because the
    /// proxy stopped returning authenticated traffic (including keepalive
    /// pongs). Auto mode uses this signal to move only the affected pool slot
    /// to TCP/Yamux.
    pub fn timed_out(&self) -> bool {
        self.inner.timed_out.load(Ordering::Acquire)
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
        self.inner
            .command_tx
            .send(ClientCommand::Register {
                flow_id,
                inbound_tx,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "原生 UDP 会话已关闭"))?;

        let stream_id = flow_id.to_string();
        Ok((
            UdpClientStream {
                flow_id,
                open_address: Some(address),
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

async fn run_session_driver(
    socket: UdpSocket,
    mut codec: UdpSessionCodec,
    mut command_rx: mpsc::Receiver<ClientCommand>,
    configured_timeout: Duration,
) -> io::Result<()> {
    let mut streams = HashMap::<u64, mpsc::Sender<Vec<u8>>>::new();
    let mut receive_buffer = vec![0_u8; UDP_MAX_DATAGRAM_SIZE + 1];
    let mut keepalive = tokio::time::interval(SESSION_KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // interval's first tick is immediate; consume it so authentication is not
    // followed by an unnecessary ping burst.
    keepalive.tick().await;
    let mut ping_token = 0_u64;
    let health_timeout = configured_timeout.max(MIN_SESSION_HEALTH_TIMEOUT);
    let mut last_authenticated_receive = Instant::now();

    loop {
        tokio::select! {
            command = command_rx.recv() => {
                let Some(command) = command else { return Ok(()) };
                let message = match command {
                    ClientCommand::Register { flow_id, inbound_tx } => {
                        streams.insert(flow_id, inbound_tx);
                        None
                    }
                    ClientCommand::OpenData { flow_id, address, data } => {
                        streams.contains_key(&flow_id).then_some(UdpSessionMessage::OpenData {
                            flow_id,
                            address,
                            data,
                        })
                    }
                    ClientCommand::Data { flow_id, data } => {
                        streams.contains_key(&flow_id).then_some(UdpSessionMessage::Data { flow_id, data })
                    }
                    ClientCommand::Close { flow_id } => {
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
                    Ok(message) => {
                        // A valid fragment also proves that the authenticated
                        // return path is alive, even before reassembly finishes.
                        last_authenticated_receive = Instant::now();
                        let Some(message) = message else { continue };
                        message
                    }
                    Err(error) => {
                        trace!("丢弃无效原生 UDP 数据报：{error}");
                        continue;
                    }
                };
                match message {
                    UdpSessionMessage::ConnectResponse { flow_id, success, error } => {
                        if !success {
                            streams.remove(&flow_id);
                            debug!(flow_id, error = ?error, "proxy 拒绝原生 UDP flow");
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
                        debug!(flow_id, reason = ?reason, "proxy 关闭原生 UDP flow");
                    }
                    UdpSessionMessage::Ping { token } => {
                        send_message(&socket, &mut codec, &UdpSessionMessage::Pong { token }).await?;
                    }
                    UdpSessionMessage::Pong { .. } => {}
                    UdpSessionMessage::OpenData { .. } => {
                        trace!("忽略 proxy 发来的意外 UDP OpenData");
                    }
                }
            }
            _ = keepalive.tick() => {
                if last_authenticated_receive.elapsed() >= health_timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "原生 UDP 会话保活响应超时",
                    ));
                }
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

#[cfg(test)]
mod tests;
