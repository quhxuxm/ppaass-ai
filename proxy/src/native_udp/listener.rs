use super::auth::prepare_session;
use super::session::{SessionContext, run_session};
use super::session_label;
use crate::config::ProxyConfig;
use crate::connection::EgressState;
use crate::error::Result;
use crate::user_manager::UserManager;
use protocol::udp_transport::{
    UDP_MAX_DATAGRAM_SIZE, UdpPacketHeader, UdpPacketKind, UdpSessionId, decode_auth_init,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, info, trace, warn};

const NATIVE_UDP_SOCKET_BUFFER_SIZE: usize = 4 * 1024 * 1024;

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
