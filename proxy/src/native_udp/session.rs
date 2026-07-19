use super::channel::run_channel_worker;
use super::session_label;
use crate::config::ProxyConfig;
use crate::connection::EgressState;
use crate::error::{ProxyError, Result};
use protocol::udp_transport::{UdpSessionCodec, UdpSessionMessage};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};
use tracing::{debug, trace, warn};

#[derive(Clone)]
pub(super) struct SessionContext {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) config: Arc<ProxyConfig>,
    pub(super) egress_state: Arc<EgressState>,
    pub(super) peer: SocketAddr,
}

struct ChannelState {
    input_tx: Option<mpsc::Sender<Vec<u8>>>,
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

pub(super) enum ChannelEvent {
    ConnectResult {
        flow_id: u64,
        response: UdpSessionMessage,
    },
    Closed {
        flow_id: u64,
        reason: Option<String>,
    },
}

pub(super) async fn run_session(
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
                    UdpSessionMessage::OpenData { flow_id, address, data } => {
                        match classify_flow_admission(
                            channels.contains_key(&flow_id),
                            channels.len(),
                            context.config.udp_session_max_flows,
                        ) {
                            FlowAdmission::Existing => {
                                // OpenData is an application datagram, not a retryable
                                // control message. Never deliver a duplicate first packet.
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
                        input_tx
                            .try_send(data)
                            .expect("new native UDP flow queue has capacity");
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

pub(super) fn udp_idle_timeout(config: &ProxyConfig) -> Duration {
    Duration::from_secs(config.udp_relay_idle_timeout_secs.max(1))
}

fn connect_response(flow_id: u64, error: Option<String>) -> UdpSessionMessage {
    UdpSessionMessage::ConnectResponse {
        flow_id,
        success: error.is_none(),
        error,
    }
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
