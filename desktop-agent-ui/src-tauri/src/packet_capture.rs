use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::fs;
#[cfg(test)]
use std::io::Cursor;
use std::io::{BufReader, ErrorKind, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::UNIX_EPOCH;

const PCAP_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;
const DLT_RAW: u32 = 101;
const MAX_RETURNED_PACKETS: usize = 5_000;
const DEFAULT_RETURNED_PACKETS: usize = 1_000;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PacketCaptureReport {
    pub(crate) file: String,
    pub(crate) exists: bool,
    pub(crate) file_size: u64,
    pub(crate) modified_at_ms: Option<u128>,
    pub(crate) total_packets: usize,
    pub(crate) returned_packets: usize,
    pub(crate) truncated: bool,
    pub(crate) upload_packets: usize,
    pub(crate) upload_bytes: u64,
    pub(crate) download_packets: usize,
    pub(crate) download_bytes: u64,
    pub(crate) packets: Vec<CapturedPacket>,
}

#[derive(Clone)]
struct CachedPacketCapture {
    path: PathBuf,
    file_size: u64,
    modified_at_ms: Option<u128>,
    limit: usize,
    report: PacketCaptureReport,
}

static PACKET_CAPTURE_CACHE: OnceLock<Mutex<Option<CachedPacketCapture>>> = OnceLock::new();

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CapturedPacket {
    pub(crate) number: usize,
    pub(crate) timestamp_ms: u64,
    pub(crate) direction: &'static str,
    pub(crate) ip_version: u8,
    pub(crate) protocol: String,
    pub(crate) sub_protocol: Option<String>,
    pub(crate) source: String,
    pub(crate) source_port: Option<u16>,
    pub(crate) destination: String,
    pub(crate) destination_port: Option<u16>,
    pub(crate) length: usize,
    pub(crate) summary: String,
    pub(crate) payload_length: usize,
    pub(crate) payload_hex: String,
    pub(crate) payload_text: String,
    pub(crate) protocol_layers: Vec<ProtocolLayer>,
    #[serde(skip)]
    tcp_sequence: Option<u32>,
    #[serde(skip)]
    payload_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProtocolLayer {
    pub(crate) name: String,
    pub(crate) summary: String,
    pub(crate) fields: Vec<ProtocolField>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProtocolField {
    pub(crate) name: String,
    pub(crate) value: String,
}

pub(crate) fn read_packet_capture(
    path: &Path,
    limit: Option<usize>,
) -> Result<PacketCaptureReport, String> {
    let file_label = path.to_string_lossy().to_string();
    let packet_limit = limit
        .unwrap_or(DEFAULT_RETURNED_PACKETS)
        .clamp(1, MAX_RETURNED_PACKETS);
    if !path.exists() {
        return Ok(PacketCaptureReport {
            file: file_label,
            exists: false,
            file_size: 0,
            modified_at_ms: None,
            total_packets: 0,
            returned_packets: 0,
            truncated: false,
            upload_packets: 0,
            upload_bytes: 0,
            download_packets: 0,
            download_bytes: 0,
            packets: Vec::new(),
        });
    }

    let metadata = fs::metadata(path).map_err(|error| format!("读取抓包文件信息失败：{error}"))?;
    let modified_at_ms = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis());
    let cache = PACKET_CAPTURE_CACHE.get_or_init(|| Mutex::new(None));
    let cached_report = cache.lock().ok().and_then(|cache_guard| {
        cache_guard
            .as_ref()
            .filter(|cached| {
                cached.path == path
                    && cached.file_size == metadata.len()
                    && cached.modified_at_ms == modified_at_ms
                    && cached.limit == packet_limit
            })
            .map(|cached| cached.report.clone())
    });
    if let Some(mut report) = cached_report {
        report.file = file_label;
        return Ok(report);
    }

    let file = fs::File::open(path).map_err(|error| format!("打开抓包文件失败：{error}"))?;
    let mut report = parse_pcap_reader(BufReader::new(file), packet_limit)?;
    report.file = file_label;
    report.exists = true;
    report.file_size = metadata.len();
    report.modified_at_ms = modified_at_ms;
    if let Ok(mut cache_guard) = cache.lock() {
        *cache_guard = Some(CachedPacketCapture {
            path: path.to_path_buf(),
            file_size: report.file_size,
            modified_at_ms,
            limit: packet_limit,
            report: report.clone(),
        });
    }
    Ok(report)
}

#[derive(Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

#[cfg(test)]
fn parse_pcap(bytes: &[u8], limit: usize) -> Result<PacketCaptureReport, String> {
    parse_pcap_reader(Cursor::new(bytes), limit)
}

fn parse_pcap_reader<R: Read>(mut reader: R, limit: usize) -> Result<PacketCaptureReport, String> {
    let mut global_header = [0u8; PCAP_HEADER_LEN];
    reader
        .read_exact(&mut global_header)
        .map_err(|_| "抓包文件不完整：缺少 PCAP 文件头".to_string())?;
    let (order, nanosecond_timestamps) = match &global_header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (ByteOrder::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (ByteOrder::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (ByteOrder::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (ByteOrder::Big, true),
        _ => return Err("不支持的抓包文件格式：仅支持 PCAP".to_string()),
    };
    if read_u32(&global_header[20..24], order) != DLT_RAW {
        return Err("抓包文件链路类型不是 DLT_RAW，无法展示 TUN IP 包".to_string());
    }

    let mut total_packets = 0usize;
    let mut packets = VecDeque::with_capacity(limit);
    let mut directions = HashMap::<String, String>::new();
    let mut upload_packets = 0usize;
    let mut upload_bytes = 0u64;
    let mut download_packets = 0usize;
    let mut download_bytes = 0u64;

    loop {
        let mut header = [0u8; PCAP_RECORD_HEADER_LEN];
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(format!("读取抓包记录失败：{error}")),
        }
        let seconds = read_u32(&header[..4], order) as u64;
        let fraction = read_u32(&header[4..8], order) as u64;
        let captured_len = read_u32(&header[8..12], order) as usize;
        let original_len = read_u32(&header[12..16], order) as usize;
        if captured_len > 16 * 1024 * 1024 {
            return Err(format!("抓包记录长度异常：{captured_len} 字节"));
        }
        let mut captured = vec![0u8; captured_len];
        match reader.read_exact(&mut captured) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(format!("读取抓包数据失败：{error}")),
        }
        total_packets += 1;
        let timestamp_ms = seconds
            .saturating_mul(1000)
            .saturating_add(if nanosecond_timestamps {
                fraction / 1_000_000
            } else {
                fraction / 1_000
            });
        if let Some(mut packet) = parse_ip_packet(
            total_packets,
            timestamp_ms,
            original_len.max(captured_len),
            &captured,
        ) {
            let flow_key = flow_key(&packet);
            let source_endpoint = endpoint(&packet.source, packet.source_port);
            let first_source = directions
                .entry(flow_key)
                .or_insert_with(|| source_endpoint.clone());
            packet.direction = if *first_source == source_endpoint {
                "upload"
            } else {
                "download"
            };
            if packet.direction == "upload" {
                upload_packets += 1;
                upload_bytes = upload_bytes.saturating_add(packet.length as u64);
            } else {
                download_packets += 1;
                download_bytes = download_bytes.saturating_add(packet.length as u64);
            }
            if packets.len() == limit {
                packets.pop_front();
            }
            packets.push_back(packet);
        }
    }

    let mut packets: Vec<_> = packets.into();
    analyze_reassembled_tcp_streams(&mut packets);
    Ok(PacketCaptureReport {
        file: String::new(),
        exists: true,
        file_size: 0,
        modified_at_ms: None,
        total_packets,
        returned_packets: packets.len(),
        truncated: total_packets > packets.len(),
        upload_packets,
        upload_bytes,
        download_packets,
        download_bytes,
        packets,
    })
}

fn parse_ip_packet(
    number: usize,
    timestamp_ms: u64,
    length: usize,
    packet: &[u8],
) -> Option<CapturedPacket> {
    match packet.first()? >> 4 {
        4 => parse_ipv4_packet(number, timestamp_ms, length, packet),
        6 => parse_ipv6_packet(number, timestamp_ms, length, packet),
        _ => None,
    }
}

fn parse_ipv4_packet(
    number: usize,
    timestamp_ms: u64,
    length: usize,
    packet: &[u8],
) -> Option<CapturedPacket> {
    if packet.len() < 20 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return None;
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string();
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string();
    Some(build_packet(
        number,
        timestamp_ms,
        4,
        packet[9],
        source,
        destination,
        length,
        &packet[header_len..],
    ))
}

fn parse_ipv6_packet(
    number: usize,
    timestamp_ms: u64,
    length: usize,
    packet: &[u8],
) -> Option<CapturedPacket> {
    if packet.len() < 40 {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?).to_string();
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?).to_string();
    Some(build_packet(
        number,
        timestamp_ms,
        6,
        packet[6],
        source,
        destination,
        length,
        &packet[40..],
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_packet(
    number: usize,
    timestamp_ms: u64,
    ip_version: u8,
    protocol_number: u8,
    source: String,
    destination: String,
    length: usize,
    transport: &[u8],
) -> CapturedPacket {
    let mut protocol_layers = vec![
        protocol_layer(
            "Frame",
            format!("{length} bytes on DLT_RAW"),
            [
                ("Packet number", number.to_string()),
                ("Timestamp", format!("{timestamp_ms} ms")),
                ("Frame length", format!("{length} bytes")),
                ("Link type", "Raw IP (DLT_RAW)".to_string()),
            ],
        ),
        protocol_layer(
            format!("Internet Protocol Version {ip_version}"),
            format!("{source} → {destination}"),
            [
                ("Version", ip_version.to_string()),
                ("Source address", source.clone()),
                ("Destination address", destination.clone()),
                ("Protocol number", protocol_number.to_string()),
                ("Packet length", format!("{length} bytes")),
            ],
        ),
    ];
    let (protocol, source_port, destination_port, summary, payload, transport_layer, tcp_sequence) =
        match protocol_number {
            6 if transport.len() >= 20 => {
                let source_port = u16::from_be_bytes([transport[0], transport[1]]);
                let destination_port = u16::from_be_bytes([transport[2], transport[3]]);
                let header_len = usize::from(transport[12] >> 4) * 4;
                let flags = tcp_flags(transport[13]);
                let payload = transport.get(header_len..).unwrap_or_default();
                (
                    "TCP".to_string(),
                    Some(source_port),
                    Some(destination_port),
                    format!("{source_port} → {destination_port} [{flags}]"),
                    payload,
                    protocol_layer(
                        "Transmission Control Protocol",
                        format!("{source_port} → {destination_port} [{flags}]"),
                        [
                            ("Source port", source_port.to_string()),
                            ("Destination port", destination_port.to_string()),
                            (
                                "Sequence number",
                                u32::from_be_bytes([
                                    transport[4],
                                    transport[5],
                                    transport[6],
                                    transport[7],
                                ])
                                .to_string(),
                            ),
                            (
                                "Acknowledgment number",
                                u32::from_be_bytes([
                                    transport[8],
                                    transport[9],
                                    transport[10],
                                    transport[11],
                                ])
                                .to_string(),
                            ),
                            ("Header length", format!("{header_len} bytes")),
                            ("Flags", format!("0x{:02x} ({flags})", transport[13])),
                            (
                                "Window size",
                                u16::from_be_bytes([transport[14], transport[15]]).to_string(),
                            ),
                            (
                                "Checksum",
                                format!(
                                    "0x{:04x}",
                                    u16::from_be_bytes([transport[16], transport[17]])
                                ),
                            ),
                            (
                                "Urgent pointer",
                                u16::from_be_bytes([transport[18], transport[19]]).to_string(),
                            ),
                            ("Payload length", format!("{} bytes", payload.len())),
                        ],
                    ),
                    Some(u32::from_be_bytes([
                        transport[4],
                        transport[5],
                        transport[6],
                        transport[7],
                    ])),
                )
            }
            17 if transport.len() >= 8 => {
                let source_port = u16::from_be_bytes([transport[0], transport[1]]);
                let destination_port = u16::from_be_bytes([transport[2], transport[3]]);
                let payload = &transport[8..];
                (
                    "UDP".to_string(),
                    Some(source_port),
                    Some(destination_port),
                    format!("{source_port} → {destination_port}"),
                    payload,
                    protocol_layer(
                        "User Datagram Protocol",
                        format!("{source_port} → {destination_port}"),
                        [
                            ("Source port", source_port.to_string()),
                            ("Destination port", destination_port.to_string()),
                            (
                                "Length",
                                format!(
                                    "{} bytes",
                                    u16::from_be_bytes([transport[4], transport[5]])
                                ),
                            ),
                            (
                                "Checksum",
                                format!(
                                    "0x{:04x}",
                                    u16::from_be_bytes([transport[6], transport[7]])
                                ),
                            ),
                            ("Payload length", format!("{} bytes", payload.len())),
                        ],
                    ),
                    None,
                )
            }
            1 => (
                "ICMP".to_string(),
                None,
                None,
                format!("type {}", transport.first().copied().unwrap_or_default()),
                transport.get(8..).unwrap_or_default(),
                icmp_layer("Internet Control Message Protocol", transport),
                None,
            ),
            58 => (
                "ICMPv6".to_string(),
                None,
                None,
                format!("type {}", transport.first().copied().unwrap_or_default()),
                transport.get(8..).unwrap_or_default(),
                icmp_layer("Internet Control Message Protocol v6", transport),
                None,
            ),
            other => (
                format!("IP/{other}"),
                None,
                None,
                format!("IP protocol {other}"),
                transport,
                protocol_layer(
                    format!("IP Protocol {other}"),
                    format!("{} bytes", transport.len()),
                    [("Payload length", format!("{} bytes", transport.len()))],
                ),
                None,
            ),
        };
    protocol_layers.push(transport_layer);
    let application_layer =
        analyze_application_protocol(&protocol, source_port, destination_port, payload);
    let sub_protocol = application_layer.as_ref().map(application_protocol_name);
    if let Some(application_layer) = application_layer {
        protocol_layers.push(application_layer);
    }
    CapturedPacket {
        number,
        timestamp_ms,
        direction: "upload",
        ip_version,
        protocol,
        sub_protocol,
        source,
        source_port,
        destination,
        destination_port,
        length,
        summary,
        payload_length: payload.len(),
        payload_hex: payload
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
        payload_text: payload
            .iter()
            .map(|byte| {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    char::from(*byte)
                } else {
                    '.'
                }
            })
            .collect(),
        protocol_layers,
        tcp_sequence,
        payload_bytes: payload.to_vec(),
    }
}

fn analyze_reassembled_tcp_streams(packets: &mut [CapturedPacket]) {
    let mut streams = HashMap::<String, Vec<usize>>::new();
    for (index, packet) in packets.iter().enumerate() {
        if packet.tcp_sequence.is_some() && !packet.payload_bytes.is_empty() {
            streams
                .entry(format!(
                    "{}:{}>{}:{}",
                    packet.source,
                    packet.source_port.unwrap_or_default(),
                    packet.destination,
                    packet.destination_port.unwrap_or_default()
                ))
                .or_default()
                .push(index);
        }
    }

    for mut indices in streams.into_values() {
        indices.sort_by_key(|index| packets[*index].tcp_sequence.unwrap_or_default());
        let Some(start_sequence) = indices
            .first()
            .and_then(|index| packets[*index].tcp_sequence)
        else {
            continue;
        };
        let mut assembled = Vec::<u8>::new();
        let mut packet_count = 0usize;
        let mut terminal_index = indices[0];
        let mut has_gap = false;
        for index in indices {
            let packet = &packets[index];
            let offset = packet
                .tcp_sequence
                .unwrap_or(start_sequence)
                .wrapping_sub(start_sequence) as usize;
            if offset > assembled.len() {
                has_gap = true;
                break;
            }
            if offset < assembled.len() {
                let overlap = assembled.len() - offset;
                if overlap < packet.payload_bytes.len() {
                    assembled.extend_from_slice(&packet.payload_bytes[overlap..]);
                }
            } else {
                assembled.extend_from_slice(&packet.payload_bytes);
            }
            packet_count += 1;
            terminal_index = index;
        }
        if packet_count < 2 {
            continue;
        }

        let source_port = packets[terminal_index].source_port;
        let destination_port = packets[terminal_index].destination_port;
        packets[terminal_index].protocol_layers.push(protocol_layer(
            "Reassembled TCP Stream",
            format!("{packet_count} segments, {} bytes", assembled.len()),
            [
                ("Segments", packet_count.to_string()),
                ("Reassembled length", format!("{} bytes", assembled.len())),
                (
                    "Sequence range",
                    format!(
                        "{}–{}",
                        start_sequence,
                        start_sequence.wrapping_add(assembled.len() as u32)
                    ),
                ),
                (
                    "Status",
                    if has_gap {
                        "Stopped at a missing segment"
                    } else {
                        "Contiguous"
                    }
                    .to_string(),
                ),
            ],
        ));
        if let Some(mut layer) =
            analyze_application_protocol("TCP", source_port, destination_port, &assembled)
        {
            packets[terminal_index].sub_protocol = Some(application_protocol_name(&layer));
            layer.summary = format!(
                "{} · reassembled from {packet_count} segments",
                layer.summary
            );
            packets[terminal_index].protocol_layers.push(layer);
        }
    }

    for packet in packets {
        packet.payload_bytes.clear();
        packet.payload_bytes.shrink_to_fit();
    }
}

fn protocol_layer(
    name: impl Into<String>,
    summary: impl Into<String>,
    fields: impl IntoIterator<Item = (impl Into<String>, String)>,
) -> ProtocolLayer {
    ProtocolLayer {
        name: name.into(),
        summary: summary.into(),
        fields: fields
            .into_iter()
            .map(|(name, value)| ProtocolField {
                name: name.into(),
                value,
            })
            .collect(),
    }
}

fn icmp_layer(name: &str, transport: &[u8]) -> ProtocolLayer {
    protocol_layer(
        name,
        format!(
            "Type {}, Code {}",
            transport.first().copied().unwrap_or_default(),
            transport.get(1).copied().unwrap_or_default()
        ),
        [
            (
                "Type",
                transport.first().copied().unwrap_or_default().to_string(),
            ),
            (
                "Code",
                transport.get(1).copied().unwrap_or_default().to_string(),
            ),
            (
                "Checksum",
                transport
                    .get(2..4)
                    .map(|bytes| format!("0x{:04x}", u16::from_be_bytes([bytes[0], bytes[1]])))
                    .unwrap_or_else(|| "Unavailable".to_string()),
            ),
            (
                "Payload length",
                format!("{} bytes", transport.len().saturating_sub(8)),
            ),
        ],
    )
}

fn analyze_application_protocol(
    protocol: &str,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    payload: &[u8],
) -> Option<ProtocolLayer> {
    if payload.is_empty() {
        return None;
    }
    if source_port == Some(53) || destination_port == Some(53) {
        return analyze_dns(protocol, payload);
    }
    if protocol == "UDP" && (source_port == Some(443) || destination_port == Some(443)) {
        return Some(analyze_quic(payload));
    }
    if payload.len() >= 5 && matches!(payload[0], 20..=23) && payload[1] == 3 {
        return Some(analyze_tls(payload));
    }
    let first_line = payload
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .map(str::trim);
    if let Some(line) = first_line.filter(|line| {
        line.starts_with("HTTP/")
            || [
                "GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ",
            ]
            .iter()
            .any(|method| line.starts_with(method))
    }) {
        return Some(analyze_http(payload, line));
    }
    None
}

fn analyze_dns(protocol: &str, payload: &[u8]) -> Option<ProtocolLayer> {
    let dns_payload = if protocol == "TCP" {
        payload.get(2..)?
    } else {
        payload
    };
    if dns_payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([dns_payload[2], dns_payload[3]]);
    let question_count = u16::from_be_bytes([dns_payload[4], dns_payload[5]]) as usize;
    let answer_count = u16::from_be_bytes([dns_payload[6], dns_payload[7]]) as usize;
    let mut fields = vec![
        (
            "Transport".to_string(),
            if protocol == "TCP" { "TCP" } else { "UDP" }.to_string(),
        ),
        (
            "Transaction ID".to_string(),
            format!(
                "0x{:04x}",
                u16::from_be_bytes([dns_payload[0], dns_payload[1]])
            ),
        ),
        ("Flags".to_string(), format!("0x{flags:04x}")),
        (
            "Message type".to_string(),
            if flags & 0x8000 == 0 {
                "Query"
            } else {
                "Response"
            }
            .to_string(),
        ),
        ("Opcode".to_string(), ((flags >> 11) & 0x0f).to_string()),
        (
            "Authoritative answer".to_string(),
            ((flags & 0x0400) != 0).to_string(),
        ),
        ("Truncated".to_string(), ((flags & 0x0200) != 0).to_string()),
        (
            "Recursion desired".to_string(),
            ((flags & 0x0100) != 0).to_string(),
        ),
        (
            "Recursion available".to_string(),
            ((flags & 0x0080) != 0).to_string(),
        ),
        ("Response code".to_string(), (flags & 0x000f).to_string()),
        ("Questions".to_string(), question_count.to_string()),
        ("Answer RRs".to_string(), answer_count.to_string()),
        (
            "Authority RRs".to_string(),
            u16::from_be_bytes([dns_payload[8], dns_payload[9]]).to_string(),
        ),
        (
            "Additional RRs".to_string(),
            u16::from_be_bytes([dns_payload[10], dns_payload[11]]).to_string(),
        ),
    ];
    let mut offset = 12usize;
    for question_index in 0..question_count.min(16) {
        let (name, next_offset) = decode_dns_name(dns_payload, offset, 0)?;
        if next_offset + 4 > dns_payload.len() {
            break;
        }
        let record_type =
            u16::from_be_bytes([dns_payload[next_offset], dns_payload[next_offset + 1]]);
        let class =
            u16::from_be_bytes([dns_payload[next_offset + 2], dns_payload[next_offset + 3]]);
        fields.push((format!("Query {} name", question_index + 1), name));
        fields.push((
            format!("Query {} type", question_index + 1),
            format!("{record_type} ({})", dns_record_type(record_type)),
        ));
        fields.push((
            format!("Query {} class", question_index + 1),
            class.to_string(),
        ));
        offset = next_offset + 4;
    }
    for answer_index in 0..answer_count.min(32) {
        let Some((name, next_offset)) = decode_dns_name(dns_payload, offset, 0) else {
            break;
        };
        if next_offset + 10 > dns_payload.len() {
            break;
        }
        let record_type =
            u16::from_be_bytes([dns_payload[next_offset], dns_payload[next_offset + 1]]);
        let class =
            u16::from_be_bytes([dns_payload[next_offset + 2], dns_payload[next_offset + 3]]);
        let ttl = u32::from_be_bytes([
            dns_payload[next_offset + 4],
            dns_payload[next_offset + 5],
            dns_payload[next_offset + 6],
            dns_payload[next_offset + 7],
        ]);
        let data_length =
            u16::from_be_bytes([dns_payload[next_offset + 8], dns_payload[next_offset + 9]])
                as usize;
        let data_offset = next_offset + 10;
        let Some(data) = dns_payload.get(data_offset..data_offset + data_length) else {
            break;
        };
        fields.push((format!("Answer {} name", answer_index + 1), name));
        fields.push((
            format!("Answer {} type", answer_index + 1),
            format!("{record_type} ({})", dns_record_type(record_type)),
        ));
        fields.push((
            format!("Answer {} class", answer_index + 1),
            class.to_string(),
        ));
        fields.push((
            format!("Answer {} TTL", answer_index + 1),
            format!("{ttl} s"),
        ));
        fields.push((
            format!("Answer {} data", answer_index + 1),
            dns_record_data(dns_payload, data_offset, record_type, data),
        ));
        offset = data_offset + data_length;
    }
    Some(protocol_layer(
        "Domain Name System",
        if flags & 0x8000 == 0 {
            "Query"
        } else {
            "Response"
        },
        fields,
    ))
}

fn decode_dns_name(data: &[u8], start: usize, depth: usize) -> Option<(String, usize)> {
    if depth > 8 || start >= data.len() {
        return None;
    }
    let mut labels = Vec::new();
    let mut offset = start;
    loop {
        let length = *data.get(offset)?;
        if length == 0 {
            return Some((
                if labels.is_empty() {
                    ".".to_string()
                } else {
                    labels.join(".")
                },
                offset + 1,
            ));
        }
        if length & 0xc0 == 0xc0 {
            let low = *data.get(offset + 1)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(low);
            let (suffix, _) = decode_dns_name(data, pointer, depth + 1)?;
            labels.push(suffix);
            return Some((labels.join("."), offset + 2));
        }
        let label_length = usize::from(length);
        if label_length > 63 {
            return None;
        }
        let label = data.get(offset + 1..offset + 1 + label_length)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        offset += label_length + 1;
    }
}

fn dns_record_type(record_type: u16) -> &'static str {
    match record_type {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        65 => "HTTPS",
        _ => "Unknown",
    }
}

fn dns_record_data(packet: &[u8], offset: usize, record_type: u16, data: &[u8]) -> String {
    match (record_type, data.len()) {
        (1, 4) => Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
        (28, 16) => <[u8; 16]>::try_from(data)
            .map(Ipv6Addr::from)
            .map(|address| address.to_string())
            .unwrap_or_else(|_| hex_bytes(data)),
        (2 | 5 | 12, _) => decode_dns_name(packet, offset, 0)
            .map(|(name, _)| name)
            .unwrap_or_else(|| hex_bytes(data)),
        _ => hex_bytes(data),
    }
}

fn analyze_http(payload: &[u8], first_line: &str) -> ProtocolLayer {
    let mut fields = vec![("Start line".to_string(), first_line.to_string())];
    let parts: Vec<_> = first_line.split_whitespace().collect();
    if first_line.starts_with("HTTP/") {
        if let Some(version) = parts.first() {
            fields.push(("Version".to_string(), (*version).to_string()));
        }
        if let Some(status) = parts.get(1) {
            fields.push(("Status code".to_string(), (*status).to_string()));
        }
        if parts.len() > 2 {
            fields.push(("Reason phrase".to_string(), parts[2..].join(" ")));
        }
    } else {
        if let Some(method) = parts.first() {
            fields.push(("Method".to_string(), (*method).to_string()));
        }
        if let Some(uri) = parts.get(1) {
            fields.push(("Request URI".to_string(), (*uri).to_string()));
        }
        if let Some(version) = parts.get(2) {
            fields.push(("Version".to_string(), (*version).to_string()));
        }
    }
    let header_end = payload
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .or_else(|| {
            payload
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 2)
        });
    if let Some(headers) = std::str::from_utf8(&payload[..header_end.unwrap_or(payload.len())]).ok()
    {
        for line in headers.lines().skip(1).take(100) {
            if let Some((name, value)) = line.trim_end_matches('\r').split_once(':') {
                fields.push((format!("Header: {}", name.trim()), value.trim().to_string()));
            }
        }
    }
    fields.push((
        "Header length".to_string(),
        format!("{} bytes", header_end.unwrap_or(payload.len())),
    ));
    fields.push((
        "Body length".to_string(),
        format!(
            "{} bytes",
            header_end
                .map(|offset| payload.len().saturating_sub(offset))
                .unwrap_or_default()
        ),
    ));
    protocol_layer("Hypertext Transfer Protocol", first_line, fields)
}

fn analyze_tls(payload: &[u8]) -> ProtocolLayer {
    let content_type = match payload[0] {
        20 => "Change Cipher Spec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application Data",
        _ => "Unknown",
    };
    let record_length = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let available_record_bytes = payload.len().saturating_sub(5).min(record_length);
    let mut fields = vec![
        (
            "Content type".to_string(),
            format!("{} ({content_type})", payload[0]),
        ),
        (
            "Legacy record version".to_string(),
            tls_version(payload[1], payload[2]),
        ),
        (
            "Record length".to_string(),
            format!("{record_length} bytes"),
        ),
        (
            "Captured record bytes".to_string(),
            format!("{available_record_bytes} of {record_length} bytes"),
        ),
    ];
    let following_bytes = payload.len().saturating_sub(5 + record_length);
    if following_bytes > 0 {
        fields.push((
            "Following TLS data".to_string(),
            format!("{following_bytes} bytes after this record"),
        ));
    }
    if payload[0] == 22 && payload.len() >= 9 {
        let handshake_type = payload[5];
        let handshake_length = (usize::from(payload[6]) << 16)
            | (usize::from(payload[7]) << 8)
            | usize::from(payload[8]);
        fields.push((
            "Handshake type".to_string(),
            format!("{handshake_type} ({})", tls_handshake_type(handshake_type)),
        ));
        fields.push((
            "Handshake length".to_string(),
            format!("{handshake_length} bytes"),
        ));
        if handshake_type == 1 {
            analyze_tls_client_hello(payload, &mut fields);
        } else if handshake_type == 2 {
            analyze_tls_server_hello(payload, &mut fields);
        }
    } else if payload[0] == 23 {
        fields.push((
            "Payload state".to_string(),
            "Encrypted application data; TLS session keys are required for inner fields"
                .to_string(),
        ));
    }
    protocol_layer("Transport Layer Security", content_type, fields)
}

fn analyze_tls_client_hello(payload: &[u8], fields: &mut Vec<(String, String)>) {
    if payload.len() < 44 {
        return;
    }
    fields.push((
        "Client version".to_string(),
        tls_version(payload[9], payload[10]),
    ));
    fields.push(("Random".to_string(), hex_bytes(&payload[11..43])));
    let session_id_length = usize::from(payload[43]);
    fields.push((
        "Session ID length".to_string(),
        session_id_length.to_string(),
    ));
    let mut offset = 44 + session_id_length;
    let Some(cipher_length_bytes) = payload.get(offset..offset + 2) else {
        return;
    };
    let cipher_length =
        u16::from_be_bytes([cipher_length_bytes[0], cipher_length_bytes[1]]) as usize;
    offset += 2;
    let Some(cipher_bytes) = payload.get(offset..offset + cipher_length) else {
        return;
    };
    fields.push((
        "Cipher suites".to_string(),
        cipher_bytes
            .chunks_exact(2)
            .map(|suite| format!("0x{:04x}", u16::from_be_bytes([suite[0], suite[1]])))
            .collect::<Vec<_>>()
            .join(", "),
    ));
    offset += cipher_length;
    let Some(compression_length) = payload.get(offset).copied() else {
        return;
    };
    offset += 1 + usize::from(compression_length);
    analyze_tls_extensions(payload, offset, fields);
}

fn analyze_tls_server_hello(payload: &[u8], fields: &mut Vec<(String, String)>) {
    if payload.len() < 44 {
        return;
    }
    fields.push((
        "Server version".to_string(),
        tls_version(payload[9], payload[10]),
    ));
    fields.push(("Random".to_string(), hex_bytes(&payload[11..43])));
    let session_id_length = usize::from(payload[43]);
    fields.push((
        "Session ID length".to_string(),
        session_id_length.to_string(),
    ));
    let offset = 44 + session_id_length;
    if let Some(bytes) = payload.get(offset..offset + 2) {
        fields.push((
            "Cipher suite".to_string(),
            format!("0x{:04x}", u16::from_be_bytes([bytes[0], bytes[1]])),
        ));
    }
    if let Some(compression) = payload.get(offset + 2) {
        fields.push(("Compression method".to_string(), compression.to_string()));
    }
    analyze_tls_extensions(payload, offset + 3, fields);
}

fn analyze_tls_extensions(payload: &[u8], offset: usize, fields: &mut Vec<(String, String)>) {
    let Some(length_bytes) = payload.get(offset..offset + 2) else {
        return;
    };
    let extensions_length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
    fields.push((
        "Extensions length".to_string(),
        format!("{extensions_length} bytes"),
    ));
    let mut cursor = offset + 2;
    let end = cursor.saturating_add(extensions_length).min(payload.len());
    let mut extension_names = Vec::new();
    while cursor + 4 <= end {
        let extension_type = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
        let extension_length =
            u16::from_be_bytes([payload[cursor + 2], payload[cursor + 3]]) as usize;
        cursor += 4;
        let Some(data) = payload.get(cursor..cursor + extension_length) else {
            break;
        };
        extension_names.push(format!(
            "{} ({extension_type})",
            tls_extension_name(extension_type)
        ));
        if extension_type == 0 && data.len() >= 5 {
            let name_length = u16::from_be_bytes([data[3], data[4]]) as usize;
            if let Some(name) = data.get(5..5 + name_length) {
                fields.push((
                    "Server Name (SNI)".to_string(),
                    String::from_utf8_lossy(name).into_owned(),
                ));
            }
        } else if extension_type == 16 && data.len() >= 3 {
            let name_length = usize::from(data[2]);
            if let Some(name) = data.get(3..3 + name_length) {
                fields.push((
                    "Application protocol (ALPN)".to_string(),
                    String::from_utf8_lossy(name).into_owned(),
                ));
            }
        } else if extension_type == 43 && data.len() >= 2 {
            let version = if data.len() == 2 {
                tls_version(data[0], data[1])
            } else if data.len() >= 3 {
                tls_version(data[1], data[2])
            } else {
                "Unknown".to_string()
            };
            fields.push(("Supported/selected version".to_string(), version));
        }
        cursor += extension_length;
    }
    if !extension_names.is_empty() {
        fields.push(("Extensions".to_string(), extension_names.join(", ")));
    }
}

fn tls_version(major: u8, minor: u8) -> String {
    let name = match (major, minor) {
        (3, 0) => "SSL 3.0",
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2 / TLS 1.3 legacy",
        (3, 4) => "TLS 1.3",
        _ => "Unknown",
    };
    format!("{major}.{minor} ({name})")
}

fn tls_handshake_type(value: u8) -> &'static str {
    match value {
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        13 => "Certificate Request",
        15 => "Certificate Verify",
        20 => "Finished",
        _ => "Unknown",
    }
}

fn tls_extension_name(value: u16) -> &'static str {
    match value {
        0 => "server_name",
        5 => "status_request",
        10 => "supported_groups",
        11 => "ec_point_formats",
        13 => "signature_algorithms",
        16 => "application_layer_protocol_negotiation",
        18 => "signed_certificate_timestamp",
        23 => "extended_master_secret",
        27 => "compress_certificate",
        35 => "session_ticket",
        43 => "supported_versions",
        45 => "psk_key_exchange_modes",
        51 => "key_share",
        _ => "unknown",
    }
}

fn analyze_quic(payload: &[u8]) -> ProtocolLayer {
    let first = payload[0];
    let long_header = first & 0x80 != 0;
    let mut fields = vec![
        (
            "Header form".to_string(),
            if long_header { "Long" } else { "Short" }.to_string(),
        ),
        ("Fixed bit".to_string(), ((first & 0x40) != 0).to_string()),
        ("First byte".to_string(), format!("0x{first:02x}")),
    ];
    let summary = if long_header {
        let packet_type = match (first >> 4) & 0x03 {
            0 => "Initial",
            1 => "0-RTT",
            2 => "Handshake",
            3 => "Retry",
            _ => "Unknown",
        };
        fields.push(("Packet type".to_string(), packet_type.to_string()));
        if payload.len() >= 6 {
            fields.push((
                "Version".to_string(),
                format!(
                    "0x{:08x}",
                    u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]])
                ),
            ));
            let destination_length = usize::from(payload[5]);
            fields.push((
                "Destination Connection ID length".to_string(),
                destination_length.to_string(),
            ));
            if let Some(destination_id) = payload.get(6..6 + destination_length) {
                fields.push((
                    "Destination Connection ID".to_string(),
                    hex_bytes(destination_id),
                ));
                let source_length_offset = 6 + destination_length;
                if let Some(source_length) = payload.get(source_length_offset).copied() {
                    let source_length = usize::from(source_length);
                    fields.push((
                        "Source Connection ID length".to_string(),
                        source_length.to_string(),
                    ));
                    if let Some(source_id) = payload
                        .get(source_length_offset + 1..source_length_offset + 1 + source_length)
                    {
                        fields.push(("Source Connection ID".to_string(), hex_bytes(source_id)));
                    }
                }
            }
        }
        packet_type
    } else {
        fields.push(("Spin bit".to_string(), ((first & 0x20) != 0).to_string()));
        fields.push((
            "Protected fields".to_string(),
            "Packet number and payload require QUIC keys".to_string(),
        ));
        "Short Header"
    };
    fields.push((
        "Protected payload".to_string(),
        format!("{} bytes", payload.len()),
    ));
    protocol_layer("QUIC", summary, fields)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn application_protocol_name(layer: &ProtocolLayer) -> String {
    match layer.name.as_str() {
        "Domain Name System" => "DNS",
        "Transport Layer Security" => "TLS",
        "Hypertext Transfer Protocol" => "HTTP",
        name => name,
    }
    .to_string()
}

fn tcp_flags(flags: u8) -> String {
    let mut names = Vec::new();
    for (mask, name) in [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ] {
        if flags & mask != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        "NONE".to_string()
    } else {
        names.join(", ")
    }
}

fn endpoint(address: &str, port: Option<u16>) -> String {
    match port {
        Some(port) => format!("{address}:{port}"),
        None => address.to_string(),
    }
}

fn flow_key(packet: &CapturedPacket) -> String {
    let left = endpoint(&packet.source, packet.source_port);
    let right = endpoint(&packet.destination, packet.destination_port);
    if left <= right {
        format!("{}|{left}|{right}", packet.protocol)
    } else {
        format!("{}|{right}|{left}", packet.protocol)
    }
}

fn read_u32(bytes: &[u8], order: ByteOrder) -> u32 {
    let array = <[u8; 4]>::try_from(bytes).unwrap_or_default();
    match order {
        ByteOrder::Little => u32::from_le_bytes(array),
        ByteOrder::Big => u32::from_be_bytes(array),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bidirectional_tcp_packets() {
        let upload = ipv4_tcp_packet([10, 0, 0, 2], [1, 1, 1, 1], 50_000, 443, 0x02);
        let download = ipv4_tcp_packet([1, 1, 1, 1], [10, 0, 0, 2], 443, 50_000, 0x12);
        let pcap = pcap_with_packets(&[upload, download]);
        let report = parse_pcap(&pcap, 100).unwrap();

        assert_eq!(report.total_packets, 2);
        assert_eq!(report.upload_packets, 1);
        assert_eq!(report.download_packets, 1);
        assert_eq!(report.packets[0].direction, "upload");
        assert_eq!(report.packets[1].direction, "download");
        assert_eq!(report.packets[0].protocol, "TCP");
    }

    #[test]
    fn keeps_only_latest_packets_at_limit() {
        let packet = ipv4_tcp_packet([10, 0, 0, 2], [1, 1, 1, 1], 50_000, 443, 0x10);
        let pcap = pcap_with_packets(&[packet.clone(), packet.clone(), packet]);
        let report = parse_pcap(&pcap, 2).unwrap();

        assert_eq!(report.total_packets, 3);
        assert_eq!(report.returned_packets, 2);
        assert!(report.truncated);
        assert_eq!(report.packets[0].number, 2);
    }

    #[test]
    fn keeps_complete_payload_and_protocol_analysis() {
        let mut transport = vec![0u8; 20];
        transport[0..2].copy_from_slice(&50_000_u16.to_be_bytes());
        transport[2..4].copy_from_slice(&443_u16.to_be_bytes());
        transport[12] = 5 << 4;
        transport[13] = 0x18;
        transport.extend(0u8..80);

        let packet = build_packet(
            1,
            1_000,
            4,
            6,
            "10.0.0.2".to_string(),
            "1.1.1.1".to_string(),
            120,
            &transport,
        );

        assert_eq!(packet.payload_length, 80);
        assert_eq!(packet.payload_hex.split_whitespace().count(), 80);
        assert_eq!(packet.protocol_layers[0].name, "Frame");
        assert!(packet
            .protocol_layers
            .iter()
            .any(|layer| layer.name == "Transmission Control Protocol"));
    }

    #[test]
    fn reassembles_segmented_tcp_application_protocol() {
        let first_payload = b"GET / HT";
        let second_payload = b"TP/1.1\r\nHost: example.com\r\n\r\n";
        let mut first_transport = vec![0u8; 20];
        first_transport[0..2].copy_from_slice(&50_000_u16.to_be_bytes());
        first_transport[2..4].copy_from_slice(&80_u16.to_be_bytes());
        first_transport[4..8].copy_from_slice(&1_000_u32.to_be_bytes());
        first_transport[12] = 5 << 4;
        first_transport[13] = 0x18;
        first_transport.extend_from_slice(first_payload);
        let mut second_transport = vec![0u8; 20];
        second_transport[0..2].copy_from_slice(&50_000_u16.to_be_bytes());
        second_transport[2..4].copy_from_slice(&80_u16.to_be_bytes());
        second_transport[4..8]
            .copy_from_slice(&(1_000_u32 + first_payload.len() as u32).to_be_bytes());
        second_transport[12] = 5 << 4;
        second_transport[13] = 0x18;
        second_transport.extend_from_slice(second_payload);

        let mut packets = vec![
            build_packet(
                1,
                1_000,
                4,
                6,
                "10.0.0.2".to_string(),
                "1.1.1.1".to_string(),
                40 + first_payload.len(),
                &first_transport,
            ),
            build_packet(
                2,
                1_001,
                4,
                6,
                "10.0.0.2".to_string(),
                "1.1.1.1".to_string(),
                40 + second_payload.len(),
                &second_transport,
            ),
        ];

        analyze_reassembled_tcp_streams(&mut packets);

        assert!(packets[1]
            .protocol_layers
            .iter()
            .any(|layer| layer.name == "Reassembled TCP Stream"));
        assert!(packets[1].protocol_layers.iter().any(|layer| {
            layer.name == "Hypertext Transfer Protocol"
                && layer.summary.contains("reassembled from 2 segments")
        }));
        let http_layer = packets[1]
            .protocol_layers
            .iter()
            .find(|layer| layer.name == "Hypertext Transfer Protocol")
            .unwrap();
        assert!(http_layer
            .fields
            .iter()
            .any(|field| field.name == "Method" && field.value == "GET"));
        assert!(http_layer
            .fields
            .iter()
            .any(|field| field.name == "Header: Host" && field.value == "example.com"));
        assert_eq!(packets[1].sub_protocol.as_deref(), Some("HTTP"));
    }

    #[test]
    fn decodes_dns_question_fields() {
        let mut dns = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        dns.extend_from_slice(b"\x07example\x03com\x00");
        dns.extend_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&1_u16.to_be_bytes());

        let layer = analyze_application_protocol("UDP", Some(50_000), Some(53), &dns).unwrap();

        assert_eq!(layer.name, "Domain Name System");
        assert!(layer
            .fields
            .iter()
            .any(|field| field.name == "Query 1 name" && field.value == "example.com"));
        assert!(layer
            .fields
            .iter()
            .any(|field| field.name == "Query 1 type" && field.value == "1 (A)"));
    }

    #[test]
    fn describes_encrypted_tls_application_payload() {
        let tls = [23, 3, 3, 0, 4, 1, 2, 3, 4];

        let layer = analyze_application_protocol("TCP", Some(50_000), Some(443), &tls).unwrap();

        assert_eq!(layer.name, "Transport Layer Security");
        assert!(layer.fields.iter().any(|field| {
            field.name == "Payload state" && field.value.contains("TLS session keys")
        }));
    }

    fn pcap_with_packets(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&0_i32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&65_535_u32.to_le_bytes());
        bytes.extend_from_slice(&DLT_RAW.to_le_bytes());
        for (index, packet) in packets.iter().enumerate() {
            bytes.extend_from_slice(&(index as u32 + 1).to_le_bytes());
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            bytes.extend_from_slice(packet);
        }
        bytes
    }

    fn ipv4_tcp_packet(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = flags;
        packet
    }
}
