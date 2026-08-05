use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::fs;
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
const PROXY_HANDSHAKE_PREFIX_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct PacketCaptureReport {
    pub file: String,
    pub exists: bool,
    pub file_size: u64,
    pub modified_at_ms: Option<u128>,
    pub total_packets: usize,
    pub returned_packets: usize,
    pub truncated: bool,
    pub upload_packets: usize,
    pub upload_bytes: u64,
    pub download_packets: usize,
    pub download_bytes: u64,
    pub packets: Vec<CapturedPacket>,
}

#[derive(Clone)]
struct CachedPacketCapture {
    path: PathBuf,
    file_size: u64,
    modified_at_ms: Option<u128>,
    limit: usize,
    proxy_listen_port: Option<u16>,
    report: PacketCaptureReport,
}

static PACKET_CAPTURE_CACHE: OnceLock<Mutex<Option<CachedPacketCapture>>> = OnceLock::new();

#[derive(Debug, Clone, Serialize)]
pub struct CapturedPacket {
    pub number: usize,
    pub timestamp_ms: u64,
    pub direction: &'static str,
    pub ip_version: u8,
    pub protocol: String,
    pub sub_protocol: Option<String>,
    pub proxy_protocol: Option<String>,
    pub source: String,
    pub source_port: Option<u16>,
    pub destination: String,
    pub destination_port: Option<u16>,
    pub length: usize,
    pub summary: String,
    pub payload_length: usize,
    pub payload_hex: String,
    pub payload_text: String,
    pub protocol_layers: Vec<ProtocolLayer>,
    #[serde(skip)]
    tcp_sequence: Option<u32>,
    #[serde(skip)]
    payload_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolLayer {
    pub name: String,
    pub summary: String,
    pub fields: Vec<ProtocolField>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolField {
    pub name: String,
    pub value: String,
}

pub fn read_packet_capture(
    path: &Path,
    limit: Option<usize>,
    proxy_listen_port: Option<u16>,
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
                    && cached.proxy_listen_port == proxy_listen_port
            })
            .map(|cached| cached.report.clone())
    });
    if let Some(mut report) = cached_report {
        report.file = file_label;
        return Ok(report);
    }

    let file = fs::File::open(path).map_err(|error| format!("打开抓包文件失败：{error}"))?;
    let mut report = parse_pcap_reader(BufReader::new(file), packet_limit, proxy_listen_port)?;
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
            proxy_listen_port,
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

pub fn parse_pcap(bytes: &[u8], limit: usize) -> Result<PacketCaptureReport, String> {
    parse_pcap_reader(Cursor::new(bytes), limit, None)
}

pub fn parse_pcap_for_proxy(
    bytes: &[u8],
    limit: usize,
    proxy_listen_port: u16,
) -> Result<PacketCaptureReport, String> {
    parse_pcap_reader(Cursor::new(bytes), limit, Some(proxy_listen_port))
}

fn parse_pcap_reader<R: Read>(
    mut reader: R,
    limit: usize,
    proxy_listen_port: Option<u16>,
) -> Result<PacketCaptureReport, String> {
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
        return Err("抓包文件链路类型不是 DLT_RAW，无法展示原始 IP 包".to_string());
    }

    let mut total_packets = 0usize;
    let mut packets = VecDeque::with_capacity(limit);
    let mut directions = HashMap::<String, String>::new();
    let mut proxy_flows = ProxyFlowTracker::new(proxy_listen_port);
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
            restrict_socks5_tcp_detection(&mut packet, proxy_listen_port);
            let flow_key = flow_key(&packet);
            packet.proxy_protocol = proxy_flows.observe(&packet, &flow_key);
            suppress_conflicting_socks5_detection(&mut packet);
            packet.direction =
                if let Some(direction) = explicit_proxy_direction(&packet, proxy_listen_port) {
                    direction
                } else {
                    let source_endpoint = endpoint(&packet.source, packet.source_port);
                    let first_source = directions
                        .entry(flow_key)
                        .or_insert_with(|| source_endpoint.clone());
                    if *first_source == source_endpoint {
                        "upload"
                    } else {
                        "download"
                    }
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
    for packet in &mut packets {
        restrict_socks5_tcp_detection(packet, proxy_listen_port);
        suppress_conflicting_socks5_detection(packet);
    }
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

fn read_u32(bytes: &[u8], order: ByteOrder) -> u32 {
    let array = <[u8; 4]>::try_from(bytes).unwrap_or_default();
    match order {
        ByteOrder::Little => u32::from_le_bytes(array),
        ByteOrder::Big => u32::from_be_bytes(array),
    }
}

mod dns;
mod ip;
mod layers;
mod quic;
mod stream;
mod web;

pub(crate) use dns::*;
pub use ip::*;
pub use layers::*;
pub use quic::*;
pub use stream::*;
pub(crate) use web::*;
