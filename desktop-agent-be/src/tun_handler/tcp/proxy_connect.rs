use super::connect_with_tun_prefetch;
use crate::direct_access::DirectAccessChecker;
use crate::error::Result;
use crate::yamux_session::{YamuxSessionManager, YamuxTargetStream};
pub use common::tls_client_hello_server_name;
use protocol::{Address, TransportProtocol};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

const TLS_SNI_PREFETCH_TIMEOUT: Duration = Duration::from_millis(250);
const TLS_SNI_PREFETCH_LIMIT: usize = 16 * 1024;

pub(super) async fn connect_proxy_stream_with_tun_prefetch(
    client: &mut netstack_smoltcp::TcpStream,
    tcp_sessions: &YamuxSessionManager,
    proxy_address: Address,
    label: &str,
    initial_prefetched: Vec<u8>,
) -> Result<(YamuxTargetStream, Vec<u8>)> {
    let sni_prefetch = if initial_prefetched.is_empty() {
        prefetch_tls_sni_for_ip(client, &proxy_address).await?
    } else {
        initial_prefetched
    };
    let proxy_address = proxy_target_address(
        proxy_address,
        tls_client_hello_server_name(&sni_prefetch).as_deref(),
    );
    let connect = tcp_sessions.connect_to_target(proxy_address, TransportProtocol::Tcp);
    let (stream, mut prefetched) = connect_with_tun_prefetch(client, connect, label).await?;
    if !sni_prefetch.is_empty() {
        let mut combined = sni_prefetch;
        combined.append(&mut prefetched);
        return Ok((stream, combined));
    }
    Ok((stream, prefetched))
}

/// 从 TLS ClientHello 恢复域名，作为 Windows DoH 未进入 TUN DNS 缓存时的
/// 受限直连判定依据。调用方必须把预读字节原样补写到最终远端。
pub fn direct_rule_tls_server_name(
    packet: &[u8],
    direct_checker: &DirectAccessChecker,
) -> Option<String> {
    let host = tls_client_hello_server_name(packet)?;
    direct_checker.is_direct_domain(&host).then_some(host)
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

pub(super) async fn prefetch_tls_sni_for_ip(
    client: &mut netstack_smoltcp::TcpStream,
    address: &Address,
) -> Result<Vec<u8>> {
    // Some Windows applications resolve through their own cache or DoH before
    // the Agent can observe DNS. Recover the TLS hostname for both IP families
    // so the Proxy does not have to connect to a stale or unsuitable CDN IP.
    // Limit the prefetch to TLS's conventional port to avoid delaying opaque
    // TCP protocols that legitimately start without sending client bytes.
    if address.port() != 443 || !matches!(address, Address::Ipv4 { .. } | Address::Ipv6 { .. }) {
        return Ok(Vec::new());
    }

    let mut packet = vec![0_u8; TLS_SNI_PREFETCH_LIMIT];
    match timeout(TLS_SNI_PREFETCH_TIMEOUT, client.read(&mut packet)).await {
        Ok(Ok(0)) | Err(_) => Ok(Vec::new()),
        Ok(Ok(read)) => {
            packet.truncate(read);
            Ok(packet)
        }
        Ok(Err(error)) => Err(error.into()),
    }
}
