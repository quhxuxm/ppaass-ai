use super::connect_with_tun_prefetch;
use crate::error::Result;
use crate::yamux_session::{YamuxSessionManager, YamuxTargetStream};
use protocol::{Address, TransportProtocol};
use std::net::SocketAddr;
use tracing::debug;

pub(super) async fn connect_proxy_stream_with_tun_prefetch(
    client: &mut netstack_smoltcp::TcpStream,
    tcp_sessions: &YamuxSessionManager,
    proxy_address: Address,
    fallback_address: Option<Address>,
    label: &str,
) -> Result<(YamuxTargetStream, Vec<u8>)> {
    let connect = async {
        match tcp_sessions
            .connect_to_target(proxy_address, TransportProtocol::Tcp)
            .await
        {
            Ok(stream) => Ok(stream),
            Err(primary_error) => {
                let Some(fallback_address) = fallback_address else {
                    return Err(primary_error);
                };
                debug!(
                    "TUN TCP 原始 IPv6 代理连接失败，使用缓存域名重试：{}；{}",
                    label, primary_error
                );
                tcp_sessions
                    .connect_to_target(fallback_address, TransportProtocol::Tcp)
                    .await
            }
        }
    };
    connect_with_tun_prefetch(client, connect, label).await
}

pub fn proxy_fallback_address(
    target: SocketAddr,
    cached_domain: Option<&str>,
) -> Option<Address> {
    if !target.is_ipv6() {
        return None;
    }
    let host = cached_domain.map(str::trim).filter(|host| !host.is_empty())?;
    Some(Address::Domain {
        host: host.to_string(),
        port: target.port(),
    })
}
