//! PPAASS 原生加密 UDP 入站。
//!
//! listener 只负责按 `session_id` 分发数据报和建立已认证会话。每个会话
//! 独占协议层 `UdpSessionCodec` 与重放窗口，再按外层 `flow_id` 将 UDP 目标
//! 分发到独立 worker。任何队列拥塞都以丢弃单个 UDP 包处理，不引入重传或有序语义。

use crate::config::{ProxyConfig, UserConfig};
use crate::connection::{
    EgressState, QueuedUdpRelayResponse, UdpRelayFlowChannels, UdpRelayFlowSet, UpstreamConnection,
    target_addr_for_address, udp_relay_channel_size,
};
use crate::error::{ProxyError, Result};
use crate::user_manager::UserManager;
use protocol::crypto::{RsaKeyPair, encrypt_oaep_sha256, verify_pss_sha256};
use protocol::udp_transport::{
    UDP_MAX_DATAGRAM_SIZE, UdpAuthInit, UdpAuthOk, UdpPacketHeader, UdpPacketKind, UdpSessionCodec,
    UdpSessionId, UdpSessionMessage, UdpSessionRole, UdpSessionSecret, decode_auth_init,
    encode_auth_ok, encode_session_secret, udp_auth_proof_digest,
};
use protocol::{Address, TransportProtocol, UdpRelayPacket};
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};
use tracing::{debug, info, trace, warn};

const NATIVE_UDP_SOCKET_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const MAX_TARGET_UDP_DATAGRAM_SIZE: usize = 65_535;

pub(crate) async fn run_listener(
    socket: Arc<UdpSocket>,
    config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    egress_state: Arc<EgressState>,
) -> Result<()> {
    configure_socket_buffers(&socket);
    let (cleanup_tx, cleanup_rx) = mpsc::unbounded_channel();
    NativeUdpListener {
        socket,
        config,
        user_manager,
        egress_state,
        sessions: HashMap::new(),
        session_tasks: JoinSet::new(),
        cleanup_tx,
        cleanup_rx,
        next_generation: 1,
    }
    .run()
    .await
}

fn configure_socket_buffers(socket: &UdpSocket) {
    let socket_ref = socket2::SockRef::from(socket);
    if let Err(error) = socket_ref.set_recv_buffer_size(NATIVE_UDP_SOCKET_BUFFER_SIZE) {
        debug!("设置原生 UDP SO_RCVBUF 失败，继续使用系统默认值：{error}");
    }
    if let Err(error) = socket_ref.set_send_buffer_size(NATIVE_UDP_SOCKET_BUFFER_SIZE) {
        debug!("设置原生 UDP SO_SNDBUF 失败，继续使用系统默认值：{error}");
    }
    debug!(
        requested = NATIVE_UDP_SOCKET_BUFFER_SIZE,
        recv = ?socket_ref.recv_buffer_size().ok(),
        send = ?socket_ref.send_buffer_size().ok(),
        "proxy 原生 UDP socket 就绪"
    );
}

struct NativeUdpListener {
    socket: Arc<UdpSocket>,
    config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    egress_state: Arc<EgressState>,
    sessions: HashMap<UdpSessionId, SessionRoute>,
    session_tasks: JoinSet<()>,
    cleanup_tx: mpsc::UnboundedSender<SessionCleanup>,
    cleanup_rx: mpsc::UnboundedReceiver<SessionCleanup>,
    next_generation: u64,
}

struct SessionRoute {
    peer: SocketAddr,
    generation: u64,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    auth_init_datagram: Vec<u8>,
    auth_ok_datagram: Arc<[u8]>,
}

#[derive(Clone, Copy)]
struct SessionCleanup {
    session_id: UdpSessionId,
    generation: u64,
}

impl NativeUdpListener {
    async fn run(mut self) -> Result<()> {
        let mut recv_buf = vec![0_u8; UDP_MAX_DATAGRAM_SIZE + 1];
        loop {
            tokio::select! {
                received = self.socket.recv_from(&mut recv_buf) => {
                    let (size, peer) = received?;
                    if size > UDP_MAX_DATAGRAM_SIZE {
                        debug!("丢弃超长原生 UDP 数据报 peer={peer} size={size}");
                        continue;
                    }
                    self.handle_datagram(peer, &recv_buf[..size]).await;
                }
                cleanup = self.cleanup_rx.recv() => {
                    let Some(cleanup) = cleanup else { continue };
                    self.remove_session(cleanup);
                }
                joined = self.session_tasks.join_next(), if !self.session_tasks.is_empty() => {
                    if let Some(Err(error)) = joined
                        && !error.is_cancelled()
                    {
                        warn!("proxy 原生 UDP 会话任务异常结束：{error}");
                    }
                }
            }
        }
    }

    async fn handle_datagram(&mut self, peer: SocketAddr, datagram: &[u8]) {
        let header = match UdpPacketHeader::decode(datagram) {
            Ok(header) => header,
            Err(error) => {
                trace!("丢弃非 PPAASS 原生 UDP 数据报 peer={peer}: {error}");
                return;
            }
        };

        match header.kind {
            UdpPacketKind::AuthInit => self.handle_auth_init(peer, datagram).await,
            UdpPacketKind::Encrypted => self.dispatch_encrypted(peer, header.session_id, datagram),
            UdpPacketKind::AuthOk => {
                trace!("proxy 收到方向错误的 AuthOk，已丢弃 peer={peer}");
            }
        }
    }

    async fn handle_auth_init(&mut self, peer: SocketAddr, datagram: &[u8]) {
        let (header, auth) = match decode_auth_init(datagram) {
            Ok(decoded) => decoded,
            Err(error) => {
                debug!("原生 UDP AuthInit 解析失败 peer={peer}: {error}");
                return;
            }
        };

        let session_id = header.session_id;
        if let Some(existing) = self.sessions.get(&session_id) {
            // AuthInit 可能因 AuthOk 丢包而重发。只对同一源地址且字节完全
            // 一致的首飞幂等重发，避免 session_id 碰撞被用来更换身份或窃取 AuthOk。
            if existing.peer == peer && existing.auth_init_datagram == datagram {
                let response = existing.auth_ok_datagram.clone();
                if let Err(error) = self.socket.send_to(response.as_ref(), peer).await {
                    debug!("重发原生 UDP AuthOk 失败 peer={peer}: {error}");
                }
            } else {
                debug!("丢弃冲突的原生 UDP AuthInit peer={peer}");
            }
            return;
        }

        if self.sessions.len() >= self.config.udp_session_limit {
            warn!(
                limit = self.config.udp_session_limit,
                peer = %peer,
                "原生 UDP 会话数已达上限，拒绝新认证"
            );
            return;
        }

        let prepared =
            match prepare_session(&self.config, &self.user_manager, session_id, &auth).await {
                Ok(prepared) => prepared,
                Err(error) => {
                    debug!(
                        "原生 UDP 认证失败 peer={peer} username={}: {error}",
                        auth.username
                    );
                    return;
                }
            };

        let generation = self.allocate_generation();
        let channel_size = self.config.udp_session_channel_size.max(1);
        let (inbound_tx, inbound_rx) = mpsc::channel(channel_size);
        let auth_ok_datagram: Arc<[u8]> = prepared.auth_ok_datagram.into();
        self.sessions.insert(
            session_id,
            SessionRoute {
                peer,
                generation,
                inbound_tx,
                auth_init_datagram: datagram.to_vec(),
                auth_ok_datagram: auth_ok_datagram.clone(),
            },
        );

        let session_context = SessionContext {
            socket: self.socket.clone(),
            config: self.config.clone(),
            egress_state: self.egress_state.clone(),
            peer,
        };
        let cleanup_tx = self.cleanup_tx.clone();
        self.session_tasks.spawn(async move {
            let _cleanup = SessionCleanupGuard {
                cleanup_tx,
                cleanup: SessionCleanup {
                    session_id,
                    generation,
                },
            };
            if let Err(error) = run_session(session_context, prepared.codec, inbound_rx).await {
                debug!(
                    "proxy 原生 UDP 会话结束 session={}: {error}",
                    session_label(&session_id)
                );
            }
        });

        if let Err(error) = self.socket.send_to(auth_ok_datagram.as_ref(), peer).await {
            debug!("发送原生 UDP AuthOk 失败 peer={peer}: {error}");
        } else {
            info!(
                "原生 UDP 会话认证成功 username={} peer={} session={} active_sessions={}",
                auth.username,
                peer,
                session_label(&session_id),
                self.sessions.len()
            );
        }
    }

    fn dispatch_encrypted(&mut self, peer: SocketAddr, session_id: UdpSessionId, datagram: &[u8]) {
        let Some(route) = self.sessions.get(&session_id) else {
            trace!("丢弃未知原生 UDP 会话的数据报 peer={peer}");
            return;
        };
        if route.peer != peer {
            debug!(
                "丢弃源地址不匹配的原生 UDP 数据报 session={} expected={} actual={}",
                session_label(&session_id),
                route.peer,
                peer
            );
            return;
        }

        match route.inbound_tx.try_send(datagram.to_vec()) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!(
                    "原生 UDP 会话入站队列已满，丢弃一个数据报 session={}",
                    session_label(&session_id)
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let cleanup = SessionCleanup {
                    session_id,
                    generation: route.generation,
                };
                self.remove_session(cleanup);
            }
        }
    }

    fn remove_session(&mut self, cleanup: SessionCleanup) {
        let should_remove = self
            .sessions
            .get(&cleanup.session_id)
            .is_some_and(|route| route.generation == cleanup.generation);
        if should_remove {
            self.sessions.remove(&cleanup.session_id);
            debug!(
                "原生 UDP 会话已清理 session={} active_sessions={}",
                session_label(&cleanup.session_id),
                self.sessions.len()
            );
        }
    }

    fn allocate_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        generation
    }
}

struct SessionCleanupGuard {
    cleanup_tx: mpsc::UnboundedSender<SessionCleanup>,
    cleanup: SessionCleanup,
}

impl Drop for SessionCleanupGuard {
    fn drop(&mut self) {
        let _ = self.cleanup_tx.send(self.cleanup);
    }
}

struct PreparedSession {
    codec: UdpSessionCodec,
    auth_ok_datagram: Vec<u8>,
}

async fn prepare_session(
    config: &ProxyConfig,
    user_manager: &UserManager,
    session_id: UdpSessionId,
    auth: &UdpAuthInit,
) -> Result<PreparedSession> {
    let user = user_manager
        .get_user(&auth.username)
        .await?
        .ok_or_else(|| ProxyError::UserNotFound(auth.username.clone()))?;
    validate_udp_auth(config, &user, auth)?;

    let user_public_key = RsaKeyPair::from_public_key_pem(&user.public_key_pem)
        .map_err(|error| ProxyError::Authentication(format!("Invalid public key: {error}")))?;
    let expected_proof = udp_auth_proof_digest(
        &session_id,
        &auth.username,
        auth.timestamp,
        &auth.client_nonce,
    );
    verify_pss_sha256(&user_public_key, &expected_proof, &auth.proof)
        .map_err(|error| ProxyError::Authentication(format!("Invalid UDP auth proof: {error}")))?;

    let mut master_key = [0_u8; 32];
    let mut server_nonce = [0_u8; 32];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut master_key);
    rng.fill_bytes(&mut server_nonce);
    let secret = UdpSessionSecret {
        session_id,
        client_nonce: auth.client_nonce,
        master_key,
        server_nonce,
    };
    let encoded_secret = encode_session_secret(&secret)
        .map_err(|error| ProxyError::Authentication(error.to_string()))?;
    let encrypted_session_secret = encrypt_oaep_sha256(&user_public_key, &encoded_secret)
        .map_err(|error| ProxyError::Authentication(error.to_string()))?;
    let auth_ok_datagram = encode_auth_ok(
        session_id,
        &UdpAuthOk {
            encrypted_session_secret,
        },
    )
    .map_err(|error| ProxyError::Authentication(error.to_string()))?;
    let codec = UdpSessionCodec::new(
        UdpSessionRole::Proxy,
        session_id,
        master_key,
        auth.client_nonce,
        server_nonce,
    )
    .map_err(|error| ProxyError::Authentication(error.to_string()))?;

    Ok(PreparedSession {
        codec,
        auth_ok_datagram,
    })
}

fn validate_udp_auth(config: &ProxyConfig, user: &UserConfig, auth: &UdpAuthInit) -> Result<()> {
    if auth.username != user.username {
        return Err(ProxyError::Authentication("Username mismatch".to_string()));
    }
    let now = common::current_timestamp();
    let tolerance = config.replay_attack_tolerance.max(0) as u64;
    if now.abs_diff(auth.timestamp) > tolerance {
        return Err(ProxyError::Authentication("Timestamp expired".to_string()));
    }
    if user.is_expired_at(now)? {
        return Err(ProxyError::Authentication("User expired".to_string()));
    }
    Ok(())
}

fn session_label(session_id: &UdpSessionId) -> String {
    hex::encode(&session_id[..6])
}

#[derive(Clone)]
struct SessionContext {
    socket: Arc<UdpSocket>,
    config: Arc<ProxyConfig>,
    egress_state: Arc<EgressState>,
    peer: SocketAddr,
}

struct ChannelState {
    input_tx: Option<mpsc::Sender<Vec<u8>>>,
    cached_connect_response: Option<UdpSessionMessage>,
    abort_handle: AbortHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowAdmission {
    Existing,
    AtCapacity,
    Create,
}

fn classify_flow_admission(
    flow_exists: bool,
    active_flow_count: usize,
    max_flows: usize,
) -> FlowAdmission {
    if flow_exists {
        FlowAdmission::Existing
    } else if active_flow_count >= max_flows {
        FlowAdmission::AtCapacity
    } else {
        FlowAdmission::Create
    }
}

enum ChannelEvent {
    ConnectResult {
        flow_id: u64,
        response: UdpSessionMessage,
    },
    Closed {
        flow_id: u64,
        reason: Option<String>,
    },
}

async fn run_session(
    context: SessionContext,
    mut codec: UdpSessionCodec,
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let channel_size = context.config.udp_session_channel_size.max(1);
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<UdpSessionMessage>(channel_size);
    let (channel_event_tx, mut channel_event_rx) = mpsc::unbounded_channel::<ChannelEvent>();
    let mut channel_tasks = JoinSet::new();
    let mut channels = HashMap::<u64, ChannelState>::new();
    let idle_timeout = udp_idle_timeout(&context.config);
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    loop {
        tokio::select! {
            _ = &mut idle => {
                debug!(
                    "原生 UDP 会话空闲超过 {} 秒，主动清理 session={}",
                    idle_timeout.as_secs(),
                    session_label(&codec.session_id())
                );
                break;
            }
            inbound = inbound_rx.recv() => {
                let Some(datagram) = inbound else { break };
                let message = match codec.decode_datagram(&datagram) {
                    Ok(message) => {
                        // codec 只会在 AEAD 校验成功后提交 replay 序号。分片尚未完整
                        // 也是有效活动；未知、重放或篡改包不得刷新 idle。
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                        message
                    }
                    Err(error) => {
                        trace!(
                            "丢弃未通过原生 UDP AEAD/replay 校验的数据报 session={}: {error}",
                            session_label(&codec.session_id())
                        );
                        continue;
                    }
                };
                let Some(message) = message else { continue };

                match message {
                    UdpSessionMessage::Connect { flow_id, address } => {
                        match classify_flow_admission(
                            channels.contains_key(&flow_id),
                            channels.len(),
                            context.config.udp_session_max_flows,
                        ) {
                            FlowAdmission::Existing => {
                                if let Some(response) = channels
                                    .get(&flow_id)
                                    .and_then(|channel| channel.cached_connect_response.clone())
                                {
                                    send_session_message(&context, &mut codec, &response).await?;
                                }
                                continue;
                            }
                            FlowAdmission::AtCapacity => {
                                debug!(
                                    flow_id,
                                    limit = context.config.udp_session_max_flows,
                                    session = %session_label(&codec.session_id()),
                                    "原生 UDP 会话 flow 数已达上限，拒绝新 flow"
                                );
                                send_session_message(
                                    &context,
                                    &mut codec,
                                    &connect_response(
                                        flow_id,
                                        Some(format!(
                                            "native UDP session flow limit reached ({})",
                                            context.config.udp_session_max_flows
                                        )),
                                    ),
                                )
                                .await?;
                                continue;
                            }
                            FlowAdmission::Create => {}
                        }

                        let (input_tx, input_rx) = mpsc::channel(channel_size);
                        let worker_context = context.clone();
                        let worker_outbound_tx = outbound_tx.clone();
                        let worker_event_tx = channel_event_tx.clone();
                        let abort_handle = channel_tasks.spawn(async move {
                            run_channel_worker(
                                worker_context,
                                flow_id,
                                address,
                                input_rx,
                                worker_outbound_tx,
                                worker_event_tx,
                            )
                            .await;
                        });
                        channels.insert(
                            flow_id,
                            ChannelState {
                                input_tx: Some(input_tx),
                                cached_connect_response: None,
                                abort_handle,
                            },
                        );
                    }
                    UdpSessionMessage::Data { flow_id, data } => {
                        let Some(channel) = channels.get_mut(&flow_id) else {
                            trace!("丢弃未连接 channel 的 UDP 数据 flow_id={flow_id}");
                            continue;
                        };
                        let Some(input_tx) = channel.input_tx.as_ref() else {
                            continue;
                        };
                        match input_tx.try_send(data) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                debug!("UDP channel 入站队列已满，丢弃一个包 flow_id={flow_id}");
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                channel.input_tx = None;
                            }
                        }
                    }
                    UdpSessionMessage::Close { flow_id, .. } => {
                        if let Some(channel) = channels.remove(&flow_id) {
                            channel.abort_handle.abort();
                        }
                    }
                    UdpSessionMessage::Ping { token } => {
                        send_session_message(
                            &context,
                            &mut codec,
                            &UdpSessionMessage::Pong { token },
                        )
                        .await?;
                    }
                    UdpSessionMessage::Pong { .. }
                    | UdpSessionMessage::ConnectResponse { .. } => {
                        trace!("proxy 收到方向错误的原生 UDP 会话消息，已忽略");
                    }
                }
            }
            outbound = outbound_rx.recv() => {
                let Some(message) = outbound else { continue };
                send_session_message(&context, &mut codec, &message).await?;
            }
            event = channel_event_rx.recv() => {
                let Some(event) = event else { continue };
                match event {
                    ChannelEvent::ConnectResult { flow_id, response } => {
                        let Some(channel) = channels.get_mut(&flow_id) else { continue };
                        let success = matches!(
                            response,
                            UdpSessionMessage::ConnectResponse { success: true, .. }
                        );
                        channel.cached_connect_response = Some(response.clone());
                        if !success {
                            channel.input_tx = None;
                        }
                        send_session_message(&context, &mut codec, &response).await?;
                    }
                    ChannelEvent::Closed { flow_id, reason } => {
                        if channels.remove(&flow_id).is_some() {
                            send_session_message(
                                &context,
                                &mut codec,
                                &UdpSessionMessage::Close { flow_id, reason },
                            )
                            .await?;
                        }
                    }
                }
            }
            joined = channel_tasks.join_next(), if !channel_tasks.is_empty() => {
                if let Some(Err(error)) = joined
                    && !error.is_cancelled()
                {
                    warn!("proxy 原生 UDP channel worker 异常结束：{error}");
                }
            }
        }
    }

    for (_, channel) in channels.drain() {
        channel.abort_handle.abort();
    }
    channel_tasks.abort_all();
    while channel_tasks.join_next().await.is_some() {}
    Ok(())
}

async fn send_session_message(
    context: &SessionContext,
    codec: &mut UdpSessionCodec,
    message: &UdpSessionMessage,
) -> Result<()> {
    let datagrams = codec
        .encode_message(message)
        .map_err(|error| ProxyError::Connection(error.to_string()))?;
    for datagram in datagrams {
        let sent = context.socket.send_to(&datagram, context.peer).await?;
        if sent != datagram.len() {
            return Err(ProxyError::Connection(format!(
                "partial native UDP send: {sent}/{}",
                datagram.len()
            )));
        }
    }
    Ok(())
}

fn udp_idle_timeout(config: &ProxyConfig) -> Duration {
    Duration::from_secs(config.udp_relay_idle_timeout_secs.max(1))
}

async fn run_channel_worker(
    context: SessionContext,
    flow_id: u64,
    address: Address,
    input_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<UdpSessionMessage>,
    event_tx: mpsc::UnboundedSender<ChannelEvent>,
) {
    if context.config.forward_mode {
        run_forward_channel(context, flow_id, address, input_rx, outbound_tx, event_tx).await;
    } else if matches!(address, Address::UdpRelay) {
        run_udp_relay_channel(context, flow_id, input_rx, outbound_tx, event_tx).await;
    } else {
        run_connected_udp_channel(context, flow_id, address, input_rx, outbound_tx, event_tx).await;
    }
}

fn connect_response(flow_id: u64, error: Option<String>) -> UdpSessionMessage {
    UdpSessionMessage::ConnectResponse {
        flow_id,
        success: error.is_none(),
        error,
    }
}

fn send_connect_result(
    event_tx: &mpsc::UnboundedSender<ChannelEvent>,
    flow_id: u64,
    error: Option<String>,
) -> bool {
    event_tx
        .send(ChannelEvent::ConnectResult {
            flow_id,
            response: connect_response(flow_id, error),
        })
        .is_ok()
}

fn send_channel_closed(
    event_tx: &mpsc::UnboundedSender<ChannelEvent>,
    flow_id: u64,
    reason: Option<String>,
) {
    let _ = event_tx.send(ChannelEvent::Closed { flow_id, reason });
}

fn try_queue_target_response(
    outbound_tx: &mpsc::Sender<UdpSessionMessage>,
    flow_id: u64,
    data: Vec<u8>,
) -> bool {
    match outbound_tx.try_send(UdpSessionMessage::Data { flow_id, data }) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            debug!("UDP channel 响应队列已满，丢弃一个目标回包 flow_id={flow_id}");
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

async fn run_connected_udp_channel(
    context: SessionContext,
    flow_id: u64,
    address: Address,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<UdpSessionMessage>,
    event_tx: mpsc::UnboundedSender<ChannelEvent>,
) {
    let target = match target_addr_for_address(&context.config, &address) {
        Ok(target) => target,
        Err(error) => {
            send_connect_result(&event_tx, flow_id, Some(error.to_string()));
            return;
        }
    };
    let socket = match context.egress_state.connect_udp(&target).await {
        Ok(socket) => socket,
        Err(error) => {
            send_connect_result(
                &event_tx,
                flow_id,
                Some(format!("Failed to connect UDP target: {error}")),
            );
            return;
        }
    };
    if !send_connect_result(&event_tx, flow_id, None) {
        return;
    }

    debug!("原生 UDP channel 已连接目标 flow_id={flow_id} target={target}");
    let idle_timeout = udp_idle_timeout(&context.config);
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let mut recv_buf = vec![0_u8; MAX_TARGET_UDP_DATAGRAM_SIZE];
    let close_reason = loop {
        tokio::select! {
            _ = &mut idle => break Some("UDP channel idle timeout".to_string()),
            input = input_rx.recv() => {
                let Some(data) = input else { break None };
                match socket.send(&data).await {
                    Ok(_) => idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout),
                    Err(error) => break Some(format!("UDP target send failed: {error}")),
                }
            }
            received = socket.recv(&mut recv_buf) => {
                match received {
                    Ok(size) => {
                        let keep_open = try_queue_target_response(
                            &outbound_tx,
                            flow_id,
                            recv_buf[..size].to_vec(),
                        );
                        if !keep_open {
                            break None;
                        }
                        // 即使响应队列满而丢包，目标 socket 本身仍有有效活动，不应更换源端口。
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    }
                    Err(error) => break Some(format!("UDP target receive failed: {error}")),
                }
            }
        }
    };
    send_channel_closed(&event_tx, flow_id, close_reason);
}

async fn run_udp_relay_channel(
    context: SessionContext,
    flow_id: u64,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<UdpSessionMessage>,
    event_tx: mpsc::UnboundedSender<ChannelEvent>,
) {
    let channel_size = udp_relay_channel_size(&context.config);
    let (response_tx, mut response_rx) = mpsc::channel::<QueuedUdpRelayResponse>(channel_size);
    let (flow_done_tx, mut flow_done_rx) = mpsc::channel::<u64>(channel_size);
    let mut flow_set = UdpRelayFlowSet::new(
        &context.config,
        context.egress_state.clone(),
        UdpRelayFlowChannels {
            response_tx,
            flow_done_tx,
        },
        "native UDP relay",
        "proxy native udp relay flow",
    );
    if !send_connect_result(&event_tx, flow_id, None) {
        return;
    }

    // 每个外层 channel 都持有自己的 UdpRelayFlowSet，因此相同的内层 flow_id
    // 不会跨 channel 冲突，也不会共享目标 socket。
    let idle_timeout = flow_set.idle_timeout().max(Duration::from_secs(1));
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let close_reason = loop {
        tokio::select! {
            _ = &mut idle => break Some("UDP relay channel idle timeout".to_string()),
            input = input_rx.recv() => {
                let Some(data) = input else { break None };
                let relay_packet = match UdpRelayPacket::decode(&data) {
                    Ok(packet) => packet,
                    Err(error) => {
                        debug!("原生 UDP relay 数据包解析失败 outer_flow_id={flow_id}: {error}");
                        continue;
                    }
                };
                flow_set.dispatch(relay_packet).await;
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            response = response_rx.recv() => {
                let Some(response) = response else { break None };
                let encoded = match response.packet.encode() {
                    Ok(encoded) => encoded,
                    Err(error) => {
                        debug!("编码原生 UDP relay 响应失败 outer_flow_id={flow_id}: {error}");
                        continue;
                    }
                };
                if !try_queue_target_response(&outbound_tx, flow_id, encoded) {
                    break None;
                }
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            done = flow_done_rx.recv() => {
                let Some(done_flow_id) = done else { break None };
                flow_set.remove(done_flow_id);
            }
        }
    };
    drop(flow_set);
    send_channel_closed(&event_tx, flow_id, close_reason);
}

async fn run_forward_channel(
    context: SessionContext,
    flow_id: u64,
    address: Address,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<UdpSessionMessage>,
    event_tx: mpsc::UnboundedSender<ChannelEvent>,
) {
    let mut upstream =
        match UpstreamConnection::connect(&context.config, address, TransportProtocol::Udp).await {
            Ok(upstream) => upstream,
            Err(error) => {
                send_connect_result(
                    &event_tx,
                    flow_id,
                    Some(format!("Upstream UDP connect failed: {error}")),
                );
                return;
            }
        };
    if !send_connect_result(&event_tx, flow_id, None) {
        upstream.close().await;
        return;
    }

    let idle_timeout = udp_idle_timeout(&context.config);
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let mut recv_buf = vec![0_u8; MAX_TARGET_UDP_DATAGRAM_SIZE];
    let close_reason = loop {
        tokio::select! {
            _ = &mut idle => break Some("Upstream UDP channel idle timeout".to_string()),
            input = input_rx.recv() => {
                let Some(data) = input else { break None };
                // UpstreamConnection 的 ClientStream 每次完整 write 会生成一个 DataPacket；
                // 显式 flush 可避免不同原生 UDP 数据报在下一跳之前滞留。
                if let Err(error) = upstream.write_all(&data).await {
                    break Some(format!("Upstream UDP write failed: {error}"));
                }
                if let Err(error) = upstream.flush().await {
                    break Some(format!("Upstream UDP flush failed: {error}"));
                }
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            received = upstream.read(&mut recv_buf) => {
                match received {
                    Ok(0) => break Some("Upstream UDP channel closed".to_string()),
                    Ok(size) => {
                        // ClientStream 一次 poll_read 最多取一个 ProxyResponse::Data；65K buffer
                        // 足以容纳合法 UDP payload，因此这里保持下一跳的数据报边界。
                        if !try_queue_target_response(
                            &outbound_tx,
                            flow_id,
                            recv_buf[..size].to_vec(),
                        ) {
                            break None;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    }
                    Err(error) => break Some(format!("Upstream UDP read failed: {error}")),
                }
            }
        }
    };
    upstream.close().await;
    send_channel_closed(&event_tx, flow_id, close_reason);
}

#[cfg(test)]
mod tests {
    use super::{FlowAdmission, classify_flow_admission};

    #[test]
    fn existing_flow_remains_idempotent_when_session_is_full() {
        assert_eq!(
            classify_flow_admission(true, 256, 256),
            FlowAdmission::Existing
        );
    }

    #[test]
    fn new_flow_is_rejected_at_limit_without_off_by_one() {
        assert_eq!(
            classify_flow_admission(false, 255, 256),
            FlowAdmission::Create
        );
        assert_eq!(
            classify_flow_admission(false, 256, 256),
            FlowAdmission::AtCapacity
        );
        assert_eq!(
            classify_flow_admission(false, 257, 256),
            FlowAdmission::AtCapacity
        );
    }

    #[test]
    fn zero_flow_limit_disables_new_flow_creation() {
        assert_eq!(
            classify_flow_admission(false, 0, 0),
            FlowAdmission::AtCapacity
        );
    }
}
