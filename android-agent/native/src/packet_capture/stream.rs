use super::*;

pub struct CapturedTcpStream {
    inner: TcpStream,
    flow: Option<TcpCaptureFlow>,
}

impl CapturedTcpStream {
    pub(super) fn new(inner: TcpStream, protocol: ProxyIngressProtocol) -> Self {
        let flow = inner
            .peer_addr()
            .ok()
            .zip(inner.local_addr().ok())
            .map(|(client, server)| TcpCaptureFlow {
                client,
                server,
                protocol,
                client_sequence: 1,
                server_sequence: 1,
            });
        Self { inner, flow }
    }
}

impl fmt::Debug for CapturedTcpStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedTcpStream")
            .field("local_addr", &self.inner.local_addr().ok())
            .field("peer_addr", &self.inner.peer_addr().ok())
            .finish_non_exhaustive()
    }
}

impl AsyncRead for CapturedTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && buf.filled().len() > filled_before
            && let Some(flow) = &mut this.flow
        {
            flow.record_client_to_server(&buf.filled()[filled_before..]);
        }
        result
    }
}

impl AsyncWrite for CapturedTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = result
            && written > 0
            && let Some(flow) = &mut this.flow
        {
            flow.record_server_to_client(&buf[..written]);
        }
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(written)) = result
            && written > 0
            && let Some(flow) = &mut this.flow
        {
            flow.record_server_to_client_vectored(bufs, written);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub struct TcpCaptureFlow {
    client: SocketAddr,
    server: SocketAddr,
    protocol: ProxyIngressProtocol,
    client_sequence: u32,
    server_sequence: u32,
}

impl TcpCaptureFlow {
    #[doc(hidden)]
    pub fn new(client: SocketAddr, server: SocketAddr, protocol: ProxyIngressProtocol) -> Self {
        Self {
            client,
            server,
            protocol,
            client_sequence: 1,
            server_sequence: 1,
        }
    }

    pub fn record_client_to_server(&mut self, payload: &[u8]) {
        self.record_payload(true, payload);
    }

    pub(super) fn record_server_to_client(&mut self, payload: &[u8]) {
        self.record_payload(false, payload);
    }

    pub(super) fn record_server_to_client_vectored(
        &mut self,
        payloads: &[IoSlice<'_>],
        written: usize,
    ) {
        let mut remaining = written;
        for payload in payloads {
            if remaining == 0 {
                break;
            }
            let captured_len = remaining.min(payload.len());
            self.record_server_to_client(&payload[..captured_len]);
            remaining -= captured_len;
        }
    }

    pub(super) fn record_payload(&mut self, client_to_server: bool, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        for chunk in payload.chunks(MAX_SYNTHETIC_TCP_PAYLOAD) {
            let (source, destination, sequence, acknowledgement) = if client_to_server {
                (
                    self.client,
                    self.server,
                    self.client_sequence,
                    self.server_sequence,
                )
            } else {
                (
                    self.server,
                    self.client,
                    self.server_sequence,
                    self.client_sequence,
                )
            };
            if is_enabled() {
                let packet = synthetic_proxy_tcp_packet(
                    source,
                    destination,
                    sequence,
                    acknowledgement,
                    chunk,
                    runtime()
                        .synthetic_packet_id
                        .fetch_add(1, Ordering::Relaxed) as u16,
                    ProxyPacketMarker {
                        protocol: self.protocol,
                        direction: if client_to_server {
                            ProxyPacketDirection::Upload
                        } else {
                            ProxyPacketDirection::Download
                        },
                    },
                );
                record(&packet);
            }
            if client_to_server {
                self.client_sequence = self.client_sequence.wrapping_add(chunk.len() as u32);
            } else {
                self.server_sequence = self.server_sequence.wrapping_add(chunk.len() as u32);
            }
        }
    }
}

#[doc(hidden)]
pub fn synthetic_proxy_tcp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgement: u32,
    payload: &[u8],
    packet_id: u16,
    marker: ProxyPacketMarker,
) -> Vec<u8> {
    let mut segment = vec![0u8; SYNTHETIC_TCP_HEADER_LEN + payload.len()];
    segment[..2].copy_from_slice(&source.port().to_be_bytes());
    segment[2..4].copy_from_slice(&destination.port().to_be_bytes());
    segment[4..8].copy_from_slice(&sequence.to_be_bytes());
    segment[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    segment[12] = ((SYNTHETIC_TCP_HEADER_LEN / 4) as u8) << 4;
    segment[13] = 0x18; // PSH + ACK
    segment[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    segment[TCP_HEADER_LEN] = PROXY_CAPTURE_TCP_OPTION_KIND;
    segment[TCP_HEADER_LEN + 1] = PROXY_CAPTURE_TCP_OPTION_LEN as u8;
    segment[TCP_HEADER_LEN + 2..TCP_HEADER_LEN + 6]
        .copy_from_slice(&PROXY_CAPTURE_TCP_OPTION_EXPERIMENT_ID);
    segment[TCP_HEADER_LEN + 6] = marker.protocol.marker_value();
    segment[TCP_HEADER_LEN + 7] = marker.direction.marker_value();
    segment[SYNTHETIC_TCP_HEADER_LEN..].copy_from_slice(payload);
    finish_transport_packet(source, destination, 6, segment, 16, packet_id)
}

#[doc(hidden)]
pub fn synthetic_tcp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgement: u32,
    payload: &[u8],
    packet_id: u16,
) -> Vec<u8> {
    synthetic_tcp_packet_with_flags(
        source,
        destination,
        sequence,
        acknowledgement,
        0x18,
        payload,
        packet_id,
    )
}

#[doc(hidden)]
pub fn synthetic_tcp_packet_with_flags(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
    packet_id: u16,
) -> Vec<u8> {
    let mut segment = vec![0u8; TCP_HEADER_LEN + payload.len()];
    segment[..2].copy_from_slice(&source.port().to_be_bytes());
    segment[2..4].copy_from_slice(&destination.port().to_be_bytes());
    segment[4..8].copy_from_slice(&sequence.to_be_bytes());
    segment[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    segment[12] = 5 << 4;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    segment[TCP_HEADER_LEN..].copy_from_slice(payload);
    finish_transport_packet(source, destination, 6, segment, 16, packet_id)
}

pub(super) fn finish_transport_packet(
    source: SocketAddr,
    destination: SocketAddr,
    protocol: u8,
    mut transport: Vec<u8>,
    checksum_offset: usize,
    packet_id: u16,
) -> Vec<u8> {
    match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            let source_ip = source.ip().octets();
            let destination_ip = destination.ip().octets();
            let transport_len = (transport.len() as u16).to_be_bytes();
            let checksum = internet_checksum(&[
                source_ip.as_slice(),
                destination_ip.as_slice(),
                &[0, protocol],
                transport_len.as_slice(),
                transport.as_slice(),
            ]);
            transport[checksum_offset..checksum_offset + 2]
                .copy_from_slice(&checksum.to_be_bytes());
            build_ipv4_packet(
                *source.ip(),
                *destination.ip(),
                protocol,
                packet_id,
                &transport,
            )
        }
        (source, destination) => {
            let source_ip = socket_addr_to_ipv6(source);
            let destination_ip = socket_addr_to_ipv6(destination);
            let source_octets = source_ip.octets();
            let destination_octets = destination_ip.octets();
            let transport_len = (transport.len() as u32).to_be_bytes();
            let checksum = internet_checksum(&[
                source_octets.as_slice(),
                destination_octets.as_slice(),
                transport_len.as_slice(),
                &[0, 0, 0, protocol],
                transport.as_slice(),
            ]);
            transport[checksum_offset..checksum_offset + 2]
                .copy_from_slice(&checksum.to_be_bytes());
            build_ipv6_packet(source_ip, destination_ip, protocol, &transport)
        }
    }
}

pub(super) fn socket_addr_to_ipv6(address: SocketAddr) -> Ipv6Addr {
    match address.ip() {
        std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        std::net::IpAddr::V6(ip) => ip,
    }
}

pub(super) fn build_ipv4_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    packet_id: u16,
    transport: &[u8],
) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN + transport.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&packet_id.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header_checksum = internet_checksum(&[&packet[..IPV4_HEADER_LEN]]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet[IPV4_HEADER_LEN..].copy_from_slice(transport);
    packet
}

pub(super) fn build_ipv6_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    protocol: u8,
    transport: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0u8; IPV6_HEADER_LEN + transport.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(transport.len() as u16).to_be_bytes());
    packet[6] = protocol;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[IPV6_HEADER_LEN..].copy_from_slice(transport);
    packet
}

pub(super) fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut pending_high_byte = None;
    for part in parts {
        let mut offset = 0usize;
        if let Some(high) = pending_high_byte.take()
            && let Some(low) = part.first()
        {
            sum += u16::from_be_bytes([high, *low]) as u32;
            offset = 1;
        }
        while offset + 1 < part.len() {
            sum += u16::from_be_bytes([part[offset], part[offset + 1]]) as u32;
            offset += 2;
        }
        if offset < part.len() {
            pending_high_byte = Some(part[offset]);
        }
    }
    if let Some(high) = pending_high_byte {
        sum += u16::from_be_bytes([high, 0]) as u32;
    }
    while sum > u16::MAX as u32 {
        sum = (sum & u16::MAX as u32) + (sum >> 16);
    }
    !(sum as u16)
}
