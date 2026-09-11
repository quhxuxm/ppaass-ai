use super::*;

use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedSender};

const DIRECT_UDP_FLOW_CHANNEL_SIZE: usize = 32;

/// A direct SOCKS UDP flow belongs to one local client and one remote target.
/// The UDP dispatcher is the only owner of its `HashMap`; workers report their
/// own completion over a channel instead of mutating a shared concurrent map.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) struct DirectUdpFlowKey {
    client: SocketAddr,
    target: Address,
}

impl DirectUdpFlowKey {
    pub(super) fn new(client: SocketAddr, target: Address) -> Self {
        Self { client, target }
    }
}

pub(super) fn spawn_direct_udp_flow(
    key: DirectUdpFlowKey,
    udp_client: Arc<UdpSocket>,
    capture_server_addr: SocketAddr,
    packet_capture: PacketCaptureController,
    closed_tx: UnboundedSender<DirectUdpFlowKey>,
) -> Sender<Vec<u8>> {
    let (tx, rx) = mpsc::channel(DIRECT_UDP_FLOW_CHANNEL_SIZE);
    tokio::spawn(run_direct_udp_flow(
        key,
        udp_client,
        capture_server_addr,
        packet_capture,
        closed_tx,
        rx,
    ));
    tx
}

async fn run_direct_udp_flow(
    key: DirectUdpFlowKey,
    udp_client: Arc<UdpSocket>,
    capture_server_addr: SocketAddr,
    packet_capture: PacketCaptureController,
    closed_tx: UnboundedSender<DirectUdpFlowKey>,
    mut rx: Receiver<Vec<u8>>,
) {
    let target_str = address_to_string(&key.target);
    info!(target = ?key.target, "新的直连 SOCKS5 UDP 会话");

    let result =
        async {
            let target_socket = connect_direct_udp(&target_str).await?;

            let write = async {
                while let Some(data) = rx.recv().await {
                    trace!(target = ?key.target, "直连 UDP 发送 {} 字节", data.len());
                    target_socket.send(&data).await.map_err(|error| {
                        AgentError::Socks5(format!("直连 UDP 发送错误: {error}"))
                    })?;
                }
                Ok::<(), AgentError>(())
            };
            let read = async {
                let mut buffer = [0u8; 65_535];
                loop {
                    let size = target_socket.recv(&mut buffer).await.map_err(|error| {
                        AgentError::Socks5(format!("直连 UDP 接收错误: {error}"))
                    })?;
                    let packet = create_udp_packet(&key.target, &buffer[..size])?;
                    udp_client
                        .send_to(&packet, key.client)
                        .await
                        .map_err(|error| {
                            AgentError::Socks5(format!("发送 UDP 数据包到客户端失败: {error}"))
                        })?;
                    packet_capture.record_udp_payload(capture_server_addr, key.client, &packet);
                }
                #[allow(unreachable_code)]
                Ok::<(), AgentError>(())
            };

            tokio::select! {
                result = write => result,
                result = read => result,
            }
        }
        .await;

    if let Err(error) = result {
        debug!(target = ?key.target, "直连 SOCKS5 UDP 会话结束: {error}");
    }
    let _ = closed_tx.send(key);
}

async fn connect_direct_udp(target: &str) -> Result<UdpSocket> {
    let candidates = tokio::net::lookup_host(target)
        .await
        .map_err(|error| AgentError::Socks5(format!("解析直连 UDP 目标 {target} 失败: {error}")))?;
    let mut last_error = None;

    for remote_addr in candidates {
        let bind_addr = match remote_addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        match UdpSocket::bind(bind_addr).await {
            Ok(socket) => match socket.connect(remote_addr).await {
                Ok(()) => return Ok(socket),
                Err(error) => last_error = Some(error),
            },
            Err(error) => last_error = Some(error),
        }
    }

    let detail = last_error
        .map(|error| error.to_string())
        .unwrap_or_else(|| "没有可用的解析地址".to_string());
    Err(AgentError::Socks5(format!(
        "直连 UDP 连接到 {target} 失败: {detail}"
    )))
}
