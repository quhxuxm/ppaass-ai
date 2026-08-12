use super::connect_with_tun_prefetch;
use crate::error::Result;
use crate::yamux_session::{YamuxSessionManager, YamuxTargetStream};
use protocol::{Address, TransportProtocol};

pub(super) async fn connect_proxy_stream_with_tun_prefetch(
    client: &mut netstack_smoltcp::TcpStream,
    tcp_sessions: &YamuxSessionManager,
    proxy_address: Address,
    label: &str,
) -> Result<(YamuxTargetStream, Vec<u8>)> {
    let connect = tcp_sessions.connect_to_target(proxy_address, TransportProtocol::Tcp);
    connect_with_tun_prefetch(client, connect, label).await
}

pub fn proxy_target_address(original: Address, cached_domain: Option<&str>) -> Address {
    match cached_domain.map(str::trim).filter(|host| !host.is_empty()) {
        Some(host) => Address::Domain {
            host: host.to_string(),
            port: original.port(),
        },
        None => original,
    }
}
