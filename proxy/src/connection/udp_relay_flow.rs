//! UDP relay flow 之间共享的小型数据结构。
//!
//! 这里的队列项会持有 `UdpRelayBufferedBytesPermit`，表示对应 payload 已经计入
//! 全局缓冲预算。队列项被发送、丢弃或任务退出时 permit Drop，预算随之释放。

use super::*;

pub(super) struct UdpRelayFlow {
    // 主 relay 循环通过这个 sender 把同一 flow_id 的上行 UDP payload 送给 flow 任务。
    pub(super) tx: tokio::sync::mpsc::Sender<QueuedUdpRelayData>,
}

pub(super) struct QueuedUdpRelayData {
    pub(super) data: Vec<u8>,
    // 持有期间表示这段上行 payload 仍在内部队列中占用内存预算。
    pub(super) _buffer_permit: UdpRelayBufferedBytesPermit,
}

pub(super) struct QueuedUdpRelayResponse {
    pub(super) packet: UdpRelayPacket,
    // 持有期间表示这段下行 payload 仍在内部队列中占用内存预算。
    pub(super) _buffer_permit: UdpRelayBufferedBytesPermit,
}

#[derive(Clone)]
pub(super) struct UdpRelayFlowChannels {
    pub(super) response_tx: tokio::sync::mpsc::Sender<QueuedUdpRelayResponse>,
    pub(super) flow_done_tx: tokio::sync::mpsc::Sender<u64>,
}

#[derive(Clone, Copy)]
pub(super) struct UdpRelayFlowOptions {
    pub(super) idle_timeout: Duration,
    pub(super) channel_size: usize,
}

pub(super) fn udp_relay_channel_size(config: &ProxyConfig) -> usize {
    config.udp_relay_channel_size.max(1)
}

pub(super) fn try_acquire_udp_relay_buffer(
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
