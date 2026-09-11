use super::*;

pub(super) fn socks_udp_target(host: &str, port: u16) -> Result<async_socks5::AddrKind> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(async_socks5::AddrKind::Ip(SocketAddr::new(ip, port)))
    } else {
        let host = host.trim();
        anyhow::ensure!(!host.is_empty(), "QUIC target host must not be empty");
        anyhow::ensure!(
            host.len() <= 255,
            "SOCKS5 UDP domain target must be at most 255 bytes"
        );
        Ok(async_socks5::AddrKind::Domain(host.to_string(), port))
    }
}

pub fn quic_version_negotiation_probe(
    worker_id: usize,
    sequence: u64,
    datagram_size: usize,
) -> Vec<u8> {
    // QUIC 服务器通常会忽略小于 1200 字节的 Initial datagram，因此这里按
    // QUIC 最小 UDP payload 约束补零。version 使用保留版本，预期服务器返回
    // Version Negotiation 包（long header + version=0）。
    let size = datagram_size.max(1200);
    let mut packet = Vec::with_capacity(size);
    packet.push(0xc0);
    packet.extend_from_slice(&0x0a0a_0a0a_u32.to_be_bytes());

    let mut dcid = [0u8; 8];
    dcid[..4].copy_from_slice(&(worker_id as u32).to_be_bytes());
    dcid[4..].copy_from_slice(&(sequence as u32).to_be_bytes());
    let mut scid = [0u8; 8];
    scid.copy_from_slice(&sequence.rotate_left(17).to_be_bytes());

    packet.push(dcid.len() as u8);
    packet.extend_from_slice(&dcid);
    packet.push(scid.len() as u8);
    packet.extend_from_slice(&scid);
    packet.resize(size, 0);
    packet
}

pub fn parse_quic_version_negotiation_response(buf: &[u8]) -> Option<Vec<u32>> {
    if buf.len() < 7 || buf[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(buf[1..5].try_into().ok()?);
    if version != 0 {
        return None;
    }

    let mut offset = 5usize;
    let dcid_len = *buf.get(offset)? as usize;
    offset += 1 + dcid_len;
    let scid_len = *buf.get(offset)? as usize;
    offset += 1 + scid_len;
    if offset > buf.len() {
        return None;
    }
    let versions = &buf[offset..];
    if versions.is_empty() || !versions.len().is_multiple_of(4) {
        return None;
    }

    Some(
        versions
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_be_bytes(*chunk))
            .collect(),
    )
}

pub fn format_quic_version(version: u32) -> String {
    format!("0x{version:08x}")
}
