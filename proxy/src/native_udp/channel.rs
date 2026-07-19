use super::session::{ChannelEvent, SessionContext, udp_idle_timeout};
use crate::connection::{
    QueuedUdpRelayResponse, UdpRelayFlowChannels, UdpRelayFlowSet, UpstreamConnection,
    target_addr_for_address, udp_relay_channel_size,
};
use protocol::udp_transport::UdpSessionMessage;
use protocol::{Address, TransportProtocol, UdpRelayPacket};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::debug;

const MAX_TARGET_UDP_DATAGRAM_SIZE: usize = 65_535;

pub(super) async fn run_channel_worker(
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
