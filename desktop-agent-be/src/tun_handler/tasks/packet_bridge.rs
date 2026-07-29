use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use common::spawn_guarded;

use super::super::PacketCaptureController;

pub(in crate::tun_handler) fn spawn_packet_bridge(
    device: Arc<tun_rs::AsyncDevice>,
    stack: netstack_smoltcp::Stack,
    mtu: usize,
    packet_capture: PacketCaptureController,
    shutdown: CancellationToken,
) -> (JoinHandle<()>, JoinHandle<()>) {
    // stack.split() 得到 TUN 包进入协议栈和协议栈包写回 TUN 的两个方向。
    let (mut stack_sink, mut stack_stream) = stack.split();

    let device_in = device.clone();
    let packet_capture_in = packet_capture.clone();
    let shutdown_in = shutdown.clone();
    let tun_to_stack = spawn_guarded("desktop tun_to_stack", async move {
        // TUN -> netstack：读取系统注入的 IP 包并交给用户态协议栈处理。
        let mut buf = vec![0u8; mtu.max(1500) + 64];
        loop {
            tokio::select! {
                _ = shutdown_in.cancelled() => break,
                read = device_in.recv(&mut buf) => {
                    match read {
                        Ok(n) if n > 0 => {
                            if let Err(error) = packet_capture_in.record(&buf[..n]) {
                                warn!("记录 TUN 上行明文包失败：{error}");
                            }
                            if !tun_packet_is_safe_for_netstack(&buf[..n]) {
                                debug!(
                                    bytes = n,
                                    "TUN 丢弃分片或长度异常的 IP 包，避免终止整个 netstack 传输流"
                                );
                                continue;
                            }
                            let pkt = buf[..n].to_vec();
                            if let Err(e) = stack_sink.send(pkt).await {
                                warn!("向 netstack 推送数据包失败：{e}");
                                break;
                            }
                        }
                        Ok(_) => continue,
                        Err(e) => {
                            error!("TUN 读取错误：{e}");
                            break;
                        }
                    }
                }
            }
        }
        debug!("tun_to_stack 任务退出");
    });

    let device_out = device;
    let packet_capture_out = packet_capture;
    let shutdown_out = shutdown;
    let stack_to_tun = spawn_guarded("desktop stack_to_tun", async move {
        // netstack -> TUN：协议栈生成的响应包写回虚拟网卡。
        loop {
            tokio::select! {
                _ = shutdown_out.cancelled() => break,
                pkt = stack_stream.next() => {
                    match pkt {
                        Some(Ok(pkt)) => {
                            if let Err(error) = packet_capture_out.record(&pkt) {
                                warn!("记录 TUN 下行明文包失败：{error}");
                            }
                            if let Err(e) = device_out.send(&pkt).await {
                                warn!("向 TUN 设备写入数据包失败：{e}");
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            warn!("netstack 流错误：{e}");
                        }
                        None => break,
                    }
                }
            }
        }
        debug!("stack_to_tun 任务退出");
    });

    (tun_to_stack, stack_to_tun)
}

pub(super) fn tun_packet_is_safe_for_netstack(packet: &[u8]) -> bool {
    let Some(version) = packet.first().map(|byte| byte >> 4) else {
        return false;
    };
    match version {
        4 => {
            if packet.len() < 20 {
                return false;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header_len < 20 || total_len < header_len || total_len > packet.len() {
                return false;
            }

            // netstack-smoltcp 0.2.2 does not reassemble IP fragments before
            // dispatching them to its TCP/UDP stream parsers. Passing a later
            // fragment there can be mistaken for a complete transport header
            // and makes the stream return None. Drop the individual fragment;
            // never let it terminate the whole Desktop UDP task.
            let fragment = u16::from_be_bytes([packet[6], packet[7]]);
            if fragment & 0x3fff != 0 {
                return false;
            }

            packet[9] != 17 || valid_udp_payload(&packet[header_len..total_len])
        }
        6 => {
            if packet.len() < 40 {
                return false;
            }
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            let total_len = 40 + payload_len;
            if total_len > packet.len() || packet[6] == 44 {
                return false;
            }
            packet[6] != 17 || valid_udp_payload(&packet[40..total_len])
        }
        _ => false,
    }
}

fn valid_udp_payload(payload: &[u8]) -> bool {
    if payload.len() < 8 {
        return false;
    }
    let declared_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    declared_len >= 8 && declared_len <= payload.len()
}
