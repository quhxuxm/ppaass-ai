use super::network::{TunNetworks, address_for_tun_target, reject_tun_target};
use crate::connection_pool::ConnectionPool;
use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::{AgentError, Result};
use crate::telemetry;
use protocol::TransportProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, info};

pub(super) async fn handle_tun_tcp(
    mut client: netstack_smoltcp::TcpStream,
    source: SocketAddr,
    target: SocketAddr,
    tun_networks: TunNetworks,
    proxy_dns: bool,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    let (address, proxy_dns_request) = address_for_tun_target(target, proxy_dns);
    if !proxy_dns_request {
        reject_tun_target("TCP", source, target, tun_networks)?;
    }
    let target_label = if proxy_dns_request {
        format!("{target} -> proxy默认DNS")
    } else {
        target.to_string()
    };

    if !proxy_dns_request && direct_checker.is_direct(&address) {
        let target_str = address_to_string(&address);
        info!("TUN TCP 直连 -> {}", target_str);
        let mut target = TcpStream::connect(&target_str)
            .await
            .map_err(|e| AgentError::Connection(format!("直连 {target_str} 失败：{e}")))?;
        match tokio::io::copy_bidirectional(&mut client, &mut target).await {
            Ok((c2t, t2c)) => {
                telemetry::emit_traffic("TUN TCP (直连)", target_label, c2t, t2c);
            }
            Err(e) => debug!("TUN TCP 直连中继结束：{e}"),
        }
        let _ = client.shutdown().await;
        return Ok(());
    }

    if proxy_dns_request {
        info!("TUN TCP DNS -> 代理 -> {}", target_label);
    } else {
        info!("TUN TCP -> 代理 -> {}", target_label);
    }
    let connected = pool
        .as_ref()
        .get_connected_stream(address, TransportProtocol::Tcp)
        .await?;
    let mut proxy_io = connected.into_async_io();
    match tokio::io::copy_bidirectional(&mut client, &mut proxy_io).await {
        Ok((c2p, p2c)) => {
            telemetry::emit_traffic("TUN TCP", target_label, c2p, p2c);
        }
        Err(e) => debug!("TUN TCP 中继结束：{e}"),
    }
    let _ = client.shutdown().await;
    Ok(())
}
