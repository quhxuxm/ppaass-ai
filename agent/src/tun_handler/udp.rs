use super::network::{TunNetworks, address_for_tun_target, reject_tun_target};
use crate::connection_pool::ConnectionPool;
use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::Result;
use crate::telemetry;
use futures::SinkExt;
use protocol::TransportProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::{debug, info};

pub(super) type UdpWriter = Arc<tokio::sync::Mutex<netstack_smoltcp::udp::WriteHalf>>;

#[derive(Clone)]
pub(super) struct UdpSessionContext {
    pub(super) tun_networks: TunNetworks,
    pub(super) proxy_dns: bool,
    pub(super) netstack_tx: UdpWriter,
    pub(super) pool: Arc<ConnectionPool>,
    pub(super) direct_checker: Arc<DirectAccessChecker>,
}

pub(super) async fn handle_tun_udp(
    client: SocketAddr,
    target: SocketAddr,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    context: UdpSessionContext,
) -> Result<()> {
    let UdpSessionContext {
        tun_networks,
        proxy_dns,
        netstack_tx,
        pool,
        direct_checker,
    } = context;

    let (address, proxy_dns_request) = address_for_tun_target(target, proxy_dns);
    if !proxy_dns_request {
        reject_tun_target("UDP", client, target, tun_networks)?;
    }
    let target_label = if proxy_dns_request {
        format!("{target} -> proxy默认DNS")
    } else {
        target.to_string()
    };

    if !proxy_dns_request && direct_checker.is_direct(&address) {
        let target_str = address_to_string(&address);
        info!("TUN UDP 直连 -> {}", target_str);
        relay_direct_udp(client, target, target_str, target_label, rx, netstack_tx).await?;
        return Ok(());
    }

    if proxy_dns_request {
        info!("TUN UDP DNS -> 代理 -> {}", target_label);
    } else {
        info!("TUN UDP -> 代理 -> {}", target_label);
    }
    let connected = pool
        .as_ref()
        .get_connected_stream(address, TransportProtocol::Udp)
        .await?;
    let proxy_io = connected.into_async_io();
    let (mut reader, mut writer) = tokio::io::split(proxy_io);

    let write = async move {
        while let Some(data) = rx.recv().await {
            if let Err(e) = writer.write_all(&data).await {
                debug!("UDP 代理写入错误：{e}");
                break;
            }
            let _ = writer.flush().await;
        }
    };
    let netstack_tx_r = netstack_tx.clone();
    let read = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let pkt = buf[..n].to_vec();
                    let mut s = netstack_tx_r.lock().await;
                    if let Err(e) = s.send((pkt, target, client)).await {
                        debug!("UDP 代理回复错误：{e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("UDP 代理读取错误：{e}");
                    break;
                }
            }
        }
    };
    tokio::select! {
        _ = write => {}
        _ = read => {}
    }

    telemetry::emit_traffic("TUN UDP", target_label, 0, 0);
    Ok(())
}

async fn relay_direct_udp(
    client: SocketAddr,
    target: SocketAddr,
    target_str: String,
    target_label: String,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    netstack_tx: UdpWriter,
) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(&target_str).await?;
    let socket = Arc::new(socket);

    let socket_w = socket.clone();
    let write = async move {
        while let Some(data) = rx.recv().await {
            if let Err(e) = socket_w.send(&data).await {
                debug!("UDP 直连发送错误：{e}");
                break;
            }
        }
    };
    let netstack_tx_r = netstack_tx.clone();
    let read = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv(&mut buf).await {
                Ok(n) => {
                    let pkt = buf[..n].to_vec();
                    let mut s = netstack_tx_r.lock().await;
                    if let Err(e) = s.send((pkt, target, client)).await {
                        debug!("UDP 直连回复错误：{e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("UDP 直连接收错误：{e}");
                    break;
                }
            }
        }
    };
    tokio::select! {
        _ = write => {}
        _ = read => {}
    }
    telemetry::emit_traffic("TUN UDP (直连)", target_label, 0, 0);
    Ok(())
}
