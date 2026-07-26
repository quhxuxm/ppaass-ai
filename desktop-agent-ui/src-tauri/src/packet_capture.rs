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
    pub(crate) source: String,
    pub(crate) source_port: Option<u16>,
    pub(crate) destination: String,
    pub(crate) destination_port: Option<u16>,
    pub(crate) length: usize,
    pub(crate) summary: String,
    pub(crate) payload_hex: String,
    pub(crate) payload_text: String,
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

    let packets: Vec<_> = packets.into();
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
    let (protocol, source_port, destination_port, summary, payload) = match protocol_number {
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
            )
        }
        17 if transport.len() >= 8 => {
            let source_port = u16::from_be_bytes([transport[0], transport[1]]);
            let destination_port = u16::from_be_bytes([transport[2], transport[3]]);
            (
                if source_port == 53 || destination_port == 53 {
                    "DNS"
                } else if source_port == 443 || destination_port == 443 {
                    "QUIC"
                } else {
                    "UDP"
                }
                .to_string(),
                Some(source_port),
                Some(destination_port),
                format!("{source_port} → {destination_port}"),
                &transport[8..],
            )
        }
        1 => (
            "ICMP".to_string(),
            None,
            None,
            format!("type {}", transport.first().copied().unwrap_or_default()),
            transport.get(8..).unwrap_or_default(),
        ),
        58 => (
            "ICMPv6".to_string(),
            None,
            None,
            format!("type {}", transport.first().copied().unwrap_or_default()),
            transport.get(8..).unwrap_or_default(),
        ),
        other => (
            format!("IP/{other}"),
            None,
            None,
            format!("IP protocol {other}"),
            transport,
        ),
    };
    let preview = &payload[..payload.len().min(48)];
    CapturedPacket {
        number,
        timestamp_ms,
        direction: "upload",
        ip_version,
        protocol,
        source,
        source_port,
        destination,
        destination_port,
        length,
        summary,
        payload_hex: preview
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
        payload_text: preview
            .iter()
            .map(|byte| {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    char::from(*byte)
                } else {
                    '.'
                }
            })
            .collect(),
    }
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
