use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DLT_RAW: u32 = 101;
const PCAP_SNAPLEN: u32 = 65_535;
const CAPTURE_QUEUE_PACKETS: usize = 4_096;
const WRITER_BATCH_PACKETS: usize = 512;
const FLUSH_INTERVAL: Duration = Duration::from_millis(250);
const MAX_RETURNED_PACKETS: usize = 2_000;

struct CaptureRuntime {
    path: Mutex<Option<PathBuf>>,
    active: ArcSwapOption<PacketWriter>,
    transition: Mutex<()>,
}

static RUNTIME: OnceLock<CaptureRuntime> = OnceLock::new();

fn runtime() -> &'static CaptureRuntime {
    RUNTIME.get_or_init(|| CaptureRuntime {
        path: Mutex::new(None),
        active: ArcSwapOption::empty(),
        transition: Mutex::new(()),
    })
}

pub(crate) fn is_enabled() -> bool {
    runtime().active.load().is_some()
}

pub(crate) fn set_enabled(path: PathBuf, enabled: bool) -> io::Result<()> {
    let state = runtime();
    let _transition = state.transition.lock();
    *state.path.lock() = Some(path.clone());
    if enabled == state.active.load().is_some() {
        return Ok(());
    }
    if enabled {
        state
            .active
            .store(Some(Arc::new(PacketWriter::create(&path)?)));
    } else {
        stop_writer(state);
    }
    Ok(())
}

pub(crate) fn clear(path: PathBuf) -> io::Result<()> {
    let state = runtime();
    let _transition = state.transition.lock();
    *state.path.lock() = Some(path.clone());
    let was_enabled = state.active.load().is_some();
    stop_writer(state);
    let writer = PacketWriter::create(&path)?;
    if was_enabled {
        state.active.store(Some(Arc::new(writer)));
    }
    Ok(())
}

pub(crate) fn record(packet: &[u8]) {
    if let Some(writer) = runtime().active.load_full() {
        let _ = writer.record(packet);
    }
}

pub(crate) fn report_json(path: &Path, limit: usize) -> Result<String, String> {
    let report = read_report(path, limit.clamp(1, MAX_RETURNED_PACKETS))?;
    serde_json::to_string(&report).map_err(|error| error.to_string())
}

fn stop_writer(state: &CaptureRuntime) {
    let Some(writer) = state.active.swap(None) else {
        return;
    };
    while Arc::strong_count(&writer) > 1 {
        thread::yield_now();
    }
    drop(writer);
}

struct CaptureRecord {
    seconds: u32,
    micros: u32,
    original_len: u32,
    packet: Vec<u8>,
}

struct PacketWriter {
    sender: Option<SyncSender<CaptureRecord>>,
    writer: Option<JoinHandle<()>>,
    dropped_packets: AtomicU64,
    disabled: AtomicBool,
}

impl PacketWriter {
    fn create(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        write_global_header(&mut file)?;
        file.flush()?;
        let (sender, receiver) = mpsc::sync_channel(CAPTURE_QUEUE_PACKETS);
        let writer = thread::Builder::new()
            .name("ppaass-android-pcap".to_string())
            .spawn(move || {
                let _ = writer_loop(file, receiver);
            })?;
        Ok(Self {
            sender: Some(sender),
            writer: Some(writer),
            dropped_packets: AtomicU64::new(0),
            disabled: AtomicBool::new(false),
        })
    }

    fn record(&self, packet: &[u8]) -> io::Result<()> {
        if self.disabled.load(Ordering::Relaxed) {
            return Ok(());
        }
        let captured_len = packet.len().min(PCAP_SNAPLEN as usize);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let record = CaptureRecord {
            seconds: now.as_secs().min(u32::MAX as u64) as u32,
            micros: now.subsec_micros(),
            original_len: packet.len().min(u32::MAX as usize) as u32,
            packet: packet[..captured_len].to_vec(),
        };
        match self.sender.as_ref().map(|sender| sender.try_send(record)) {
            Some(Ok(())) | None => Ok(()),
            Some(Err(TrySendError::Full(_))) => {
                self.dropped_packets.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Some(Err(TrySendError::Disconnected(_))) => {
                self.disabled.store(true, Ordering::Relaxed);
                Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    "capture writer stopped",
                ))
            }
        }
    }
}

impl Drop for PacketWriter {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

fn writer_loop(file: File, receiver: Receiver<CaptureRecord>) -> io::Result<()> {
    let mut writer = BufWriter::with_capacity(256 * 1024, file);
    let mut last_flush = Instant::now();
    loop {
        match receiver.recv_timeout(FLUSH_INTERVAL) {
            Ok(record) => {
                write_record(&mut writer, record)?;
                for _ in 1..WRITER_BATCH_PACKETS {
                    match receiver.try_recv() {
                        Ok(record) => write_record(&mut writer, record)?,
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            writer.flush()?;
                            return Ok(());
                        }
                    }
                }
                if last_flush.elapsed() >= FLUSH_INTERVAL {
                    writer.flush()?;
                    last_flush = Instant::now();
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                writer.flush()?;
                last_flush = Instant::now();
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    writer.flush()
}

fn write_record(writer: &mut impl Write, record: CaptureRecord) -> io::Result<()> {
    writer.write_all(&record.seconds.to_le_bytes())?;
    writer.write_all(&record.micros.to_le_bytes())?;
    writer.write_all(&(record.packet.len() as u32).to_le_bytes())?;
    writer.write_all(&record.original_len.to_le_bytes())?;
    writer.write_all(&record.packet)
}

fn write_global_header(file: &mut File) -> io::Result<()> {
    file.write_all(&0xa1b2c3d4_u32.to_le_bytes())?;
    file.write_all(&2_u16.to_le_bytes())?;
    file.write_all(&4_u16.to_le_bytes())?;
    file.write_all(&0_i32.to_le_bytes())?;
    file.write_all(&0_u32.to_le_bytes())?;
    file.write_all(&PCAP_SNAPLEN.to_le_bytes())?;
    file.write_all(&DLT_RAW.to_le_bytes())
}

#[derive(Serialize)]
struct CaptureReport {
    exists: bool,
    file_size: u64,
    total_packets: usize,
    packets: Vec<CapturedPacket>,
}

#[derive(Clone, Serialize)]
struct CapturedPacket {
    number: usize,
    timestamp_ms: u64,
    direction: &'static str,
    ip_version: u8,
    protocol: String,
    sub_protocol: Option<String>,
    source: String,
    source_port: Option<u16>,
    destination: String,
    destination_port: Option<u16>,
    length: usize,
    summary: String,
    payload_length: usize,
    payload_hex: String,
    payload_text: String,
    protocol_layers: Vec<ProtocolLayer>,
    #[serde(skip)]
    tcp_sequence: Option<u32>,
    #[serde(skip)]
    payload: Vec<u8>,
}

#[derive(Clone, Serialize)]
struct ProtocolLayer {
    name: String,
    summary: String,
    fields: Vec<ProtocolField>,
}

#[derive(Clone, Serialize)]
struct ProtocolField {
    name: String,
    value: String,
}

fn read_report(path: &Path, limit: usize) -> Result<CaptureReport, String> {
    if !path.exists() {
        return Ok(CaptureReport {
            exists: false,
            file_size: 0,
            total_packets: 0,
            packets: Vec::new(),
        });
    }
    let file_size = std::fs::metadata(path)
        .map_err(|error| error.to_string())?
        .len();
    let file = File::open(path).map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(file);
    let mut global = [0u8; 24];
    reader
        .read_exact(&mut global)
        .map_err(|_| "PCAP header is incomplete".to_string())?;
    if global[..4] != [0xd4, 0xc3, 0xb2, 0xa1]
        || u32::from_le_bytes(global[20..24].try_into().unwrap()) != DLT_RAW
    {
        return Err("Unsupported PCAP format".to_string());
    }
    let mut total_packets = 0usize;
    let mut packets = VecDeque::with_capacity(limit);
    let mut directions = HashMap::<String, String>::new();
    loop {
        let mut header = [0u8; 16];
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error.to_string()),
        }
        let seconds = u32::from_le_bytes(header[..4].try_into().unwrap()) as u64;
        let micros = u32::from_le_bytes(header[4..8].try_into().unwrap()) as u64;
        let captured_len = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        let original_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        if captured_len > 16 * 1024 * 1024 {
            return Err("Invalid packet length".to_string());
        }
        let mut bytes = vec![0; captured_len];
        if reader.read_exact(&mut bytes).is_err() {
            break;
        }
        total_packets += 1;
        if let Some(mut packet) = parse_ip_packet(
            total_packets,
            seconds * 1000 + micros / 1000,
            original_len.max(captured_len),
            &bytes,
        ) {
            let source = endpoint(&packet.source, packet.source_port);
            let key = flow_key(&packet);
            let first_source = directions.entry(key).or_insert_with(|| source.clone());
            packet.direction = if *first_source == source {
                "upload"
            } else {
                "download"
            };
            if packets.len() == limit {
                packets.pop_front();
            }
            packets.push_back(packet);
        }
    }
    let mut packets: Vec<_> = packets.into();
    reassemble_tcp(&mut packets);
    Ok(CaptureReport {
        exists: true,
        file_size,
        total_packets,
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
        4 if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            build_packet(
                number,
                timestamp_ms,
                4,
                packet[9],
                (
                    Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string(),
                    Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string(),
                ),
                length,
                packet.get(header_len..)?,
            )
        }
        6 if packet.len() >= 40 => build_packet(
            number,
            timestamp_ms,
            6,
            packet[6],
            (
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?).to_string(),
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?).to_string(),
            ),
            length,
            &packet[40..],
        ),
        _ => None,
    }
}

fn build_packet(
    number: usize,
    timestamp_ms: u64,
    ip_version: u8,
    protocol_number: u8,
    addresses: (String, String),
    length: usize,
    transport: &[u8],
) -> Option<CapturedPacket> {
    let (source, destination) = addresses;
    let (protocol, source_port, destination_port, summary, payload, tcp_sequence, transport_fields) =
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
                    Some(u32::from_be_bytes(transport[4..8].try_into().unwrap())),
                    vec![
                        field("Source port", source_port),
                        field("Destination port", destination_port),
                        field(
                            "Sequence number",
                            u32::from_be_bytes(transport[4..8].try_into().unwrap()),
                        ),
                        field(
                            "Acknowledgment number",
                            u32::from_be_bytes(transport[8..12].try_into().unwrap()),
                        ),
                        field("Header length", format!("{header_len} bytes")),
                        field("Flags", format!("0x{:02x} ({flags})", transport[13])),
                        field(
                            "Window size",
                            u16::from_be_bytes([transport[14], transport[15]]),
                        ),
                        field("Payload length", format!("{} bytes", payload.len())),
                    ],
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
                    None,
                    vec![
                        field("Source port", source_port),
                        field("Destination port", destination_port),
                        field("Length", u16::from_be_bytes([transport[4], transport[5]])),
                        field("Payload length", format!("{} bytes", payload.len())),
                    ],
                )
            }
            1 => (
                "ICMP".to_string(),
                None,
                None,
                format!("type {}", transport.first().copied().unwrap_or_default()),
                transport.get(8..).unwrap_or_default(),
                None,
                vec![
                    field("Type", transport.first().copied().unwrap_or_default()),
                    field("Code", transport.get(1).copied().unwrap_or_default()),
                ],
            ),
            58 => (
                "ICMPv6".to_string(),
                None,
                None,
                format!("type {}", transport.first().copied().unwrap_or_default()),
                transport.get(8..).unwrap_or_default(),
                None,
                vec![
                    field("Type", transport.first().copied().unwrap_or_default()),
                    field("Code", transport.get(1).copied().unwrap_or_default()),
                ],
            ),
            other => (
                format!("IP/{other}"),
                None,
                None,
                format!("IP protocol {other}"),
                transport,
                None,
                vec![field("Protocol number", other)],
            ),
        };
    let application = analyze_application(&protocol, source_port, destination_port, payload);
    let sub_protocol = application
        .as_ref()
        .map(|layer| short_protocol(&layer.name));
    let transport_name = match protocol.as_str() {
        "TCP" => "Transmission Control Protocol",
        "UDP" => "User Datagram Protocol",
        value => value,
    };
    let mut protocol_layers = vec![
        layer(
            "Frame",
            format!("{length} bytes on DLT_RAW"),
            vec![
                field("Packet number", number),
                field("Frame length", format!("{length} bytes")),
            ],
        ),
        layer(
            format!("Internet Protocol Version {ip_version}"),
            format!("{source} → {destination}"),
            vec![
                field("Version", ip_version),
                field("Source address", source.clone()),
                field("Destination address", destination.clone()),
                field("Protocol number", protocol_number),
            ],
        ),
        layer(transport_name, summary.clone(), transport_fields),
    ];
    if let Some(application) = application {
        protocol_layers.push(application);
    }
    Some(CapturedPacket {
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
        payload_hex: hex(payload),
        payload_text: ascii(payload),
        protocol_layers,
        tcp_sequence,
        payload: payload.to_vec(),
    })
}

fn analyze_application(
    protocol: &str,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    payload: &[u8],
) -> Option<ProtocolLayer> {
    if payload.is_empty() {
        return None;
    }
    if source_port == Some(53) || destination_port == Some(53) {
        let bytes = if protocol == "TCP" {
            payload.get(2..)?
        } else {
            payload
        };
        if bytes.len() < 12 {
            return None;
        }
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let mut fields = vec![
            field(
                "Transaction ID",
                format!("0x{:04x}", u16::from_be_bytes([bytes[0], bytes[1]])),
            ),
            field("Flags", format!("0x{flags:04x}")),
            field(
                "Message type",
                if flags & 0x8000 == 0 {
                    "Query"
                } else {
                    "Response"
                },
            ),
            field("Questions", u16::from_be_bytes([bytes[4], bytes[5]])),
            field("Answer RRs", u16::from_be_bytes([bytes[6], bytes[7]])),
            field("Authority RRs", u16::from_be_bytes([bytes[8], bytes[9]])),
            field("Additional RRs", u16::from_be_bytes([bytes[10], bytes[11]])),
        ];
        if let Some((name, offset)) = dns_name(bytes, 12, 0)
            && offset + 4 <= bytes.len()
        {
            fields.push(field("Query name", name));
            fields.push(field(
                "Query type",
                u16::from_be_bytes([bytes[offset], bytes[offset + 1]]),
            ));
            fields.push(field(
                "Query class",
                u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]),
            ));
        }
        return Some(layer(
            "Domain Name System",
            if flags & 0x8000 == 0 {
                "Query"
            } else {
                "Response"
            },
            fields,
        ));
    }
    if protocol == "UDP" && (source_port == Some(443) || destination_port == Some(443)) {
        let first = payload[0];
        let long = first & 0x80 != 0;
        let mut fields = vec![
            field("Header form", if long { "Long" } else { "Short" }),
            field("Fixed bit", first & 0x40 != 0),
            field("First byte", format!("0x{first:02x}")),
        ];
        if long && payload.len() >= 6 {
            fields.push(field(
                "Packet type",
                match (first >> 4) & 3 {
                    0 => "Initial",
                    1 => "0-RTT",
                    2 => "Handshake",
                    _ => "Retry",
                },
            ));
            fields.push(field(
                "Version",
                format!(
                    "0x{:08x}",
                    u32::from_be_bytes(payload[1..5].try_into().unwrap())
                ),
            ));
            let dcid_len = usize::from(payload[5]);
            fields.push(field("DCID length", dcid_len));
            if let Some(dcid) = payload.get(6..6 + dcid_len) {
                fields.push(field("DCID", hex(dcid)));
            }
        } else if !long {
            fields.push(field(
                "Protected fields",
                "Packet number and payload require QUIC keys",
            ));
        }
        return Some(layer(
            "QUIC",
            if long { "Long Header" } else { "Short Header" },
            fields,
        ));
    }
    if payload.len() >= 5 && matches!(payload[0], 20..=23) && payload[1] == 3 {
        let content = match payload[0] {
            20 => "Change Cipher Spec",
            21 => "Alert",
            22 => "Handshake",
            23 => "Application Data",
            _ => "Unknown",
        };
        let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
        let mut fields = vec![
            field("Content type", format!("{} ({content})", payload[0])),
            field("Legacy version", format!("{}.{}", payload[1], payload[2])),
            field("Record length", format!("{record_len} bytes")),
            field(
                "Captured record bytes",
                format!(
                    "{} of {record_len} bytes",
                    payload.len().saturating_sub(5).min(record_len)
                ),
            ),
        ];
        if payload[0] == 22 && payload.len() >= 9 {
            fields.push(field("Handshake type", payload[5]));
            fields.push(field(
                "Handshake length",
                (usize::from(payload[6]) << 16)
                    | (usize::from(payload[7]) << 8)
                    | usize::from(payload[8]),
            ));
        } else if payload[0] == 23 {
            fields.push(field(
                "Payload state",
                "Encrypted; TLS session keys are required",
            ));
        }
        return Some(layer("Transport Layer Security", content, fields));
    }
    let text = std::str::from_utf8(payload).ok()?;
    let first_line = text.lines().next()?.trim_end_matches('\r');
    if first_line.starts_with("HTTP/")
        || [
            "GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ",
        ]
        .iter()
        .any(|method| first_line.starts_with(method))
    {
        let mut fields = vec![field("Start line", first_line)];
        let parts: Vec<_> = first_line.split_whitespace().collect();
        if first_line.starts_with("HTTP/") {
            if let Some(value) = parts.first() {
                fields.push(field("Version", *value));
            }
            if let Some(value) = parts.get(1) {
                fields.push(field("Status code", *value));
            }
        } else {
            if let Some(value) = parts.first() {
                fields.push(field("Method", *value));
            }
            if let Some(value) = parts.get(1) {
                fields.push(field("Request URI", *value));
            }
            if let Some(value) = parts.get(2) {
                fields.push(field("Version", *value));
            }
        }
        for line in text.lines().skip(1).take(100) {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                fields.push(field(format!("Header: {}", name.trim()), value.trim()));
            }
        }
        return Some(layer("Hypertext Transfer Protocol", first_line, fields));
    }
    None
}

fn reassemble_tcp(packets: &mut [CapturedPacket]) {
    let mut streams = HashMap::<String, Vec<usize>>::new();
    for (index, packet) in packets.iter().enumerate() {
        if packet.tcp_sequence.is_some() && !packet.payload.is_empty() {
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
        let Some(start) = indices
            .first()
            .and_then(|index| packets[*index].tcp_sequence)
        else {
            continue;
        };
        let mut assembled = Vec::new();
        let mut count = 0usize;
        let mut terminal = indices[0];
        for index in indices {
            let packet = &packets[index];
            let offset = packet.tcp_sequence.unwrap_or(start).wrapping_sub(start) as usize;
            if offset > assembled.len() {
                break;
            }
            let overlap = assembled.len().saturating_sub(offset);
            if overlap < packet.payload.len() {
                assembled.extend_from_slice(&packet.payload[overlap..]);
            }
            count += 1;
            terminal = index;
        }
        if count > 1 {
            packets[terminal].protocol_layers.push(layer(
                "Reassembled TCP Stream",
                format!("{count} segments, {} bytes", assembled.len()),
                vec![
                    field("Segments", count),
                    field("Reassembled length", format!("{} bytes", assembled.len())),
                    field("Sequence start", start),
                ],
            ));
            if let Some(mut app) = analyze_application(
                "TCP",
                packets[terminal].source_port,
                packets[terminal].destination_port,
                &assembled,
            ) {
                packets[terminal].sub_protocol = Some(short_protocol(&app.name));
                app.summary = format!("{} · reassembled from {count} segments", app.summary);
                packets[terminal].protocol_layers.push(app);
            }
        }
    }
    for packet in packets {
        packet.payload.clear();
        packet.payload.shrink_to_fit();
    }
}

fn dns_name(data: &[u8], start: usize, depth: usize) -> Option<(String, usize)> {
    if depth > 8 {
        return None;
    }
    let mut labels = Vec::new();
    let mut offset = start;
    loop {
        let len = *data.get(offset)?;
        if len == 0 {
            return Some((
                if labels.is_empty() {
                    ".".to_string()
                } else {
                    labels.join(".")
                },
                offset + 1,
            ));
        }
        if len & 0xc0 == 0xc0 {
            let pointer = (usize::from(len & 0x3f) << 8) | usize::from(*data.get(offset + 1)?);
            labels.push(dns_name(data, pointer, depth + 1)?.0);
            return Some((labels.join("."), offset + 2));
        }
        let label = data.get(offset + 1..offset + 1 + usize::from(len))?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        offset += usize::from(len) + 1;
    }
}

fn field(name: impl Into<String>, value: impl ToString) -> ProtocolField {
    ProtocolField {
        name: name.into(),
        value: value.to_string(),
    }
}

fn layer(
    name: impl Into<String>,
    summary: impl Into<String>,
    fields: Vec<ProtocolField>,
) -> ProtocolLayer {
    ProtocolLayer {
        name: name.into(),
        summary: summary.into(),
        fields,
    }
}

fn short_protocol(name: &str) -> String {
    match name {
        "Domain Name System" => "DNS",
        "Transport Layer Security" => "TLS",
        "Hypertext Transfer Protocol" => "HTTP",
        value => value,
    }
    .to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect()
}

fn tcp_flags(flags: u8) -> String {
    let mut names = Vec::new();
    for (mask, name) in [
        (1, "FIN"),
        (2, "SYN"),
        (4, "RST"),
        (8, "PSH"),
        (16, "ACK"),
        (32, "URG"),
        (64, "ECE"),
        (128, "CWR"),
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
    port.map(|port| format!("{address}:{port}"))
        .unwrap_or_else(|| address.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_defaults_disabled() {
        assert!(!is_enabled());
    }

    #[test]
    fn parses_http_fields() {
        let layer = analyze_application(
            "TCP",
            Some(50000),
            Some(80),
            b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(short_protocol(&layer.name), "HTTP");
        assert!(
            layer
                .fields
                .iter()
                .any(|field| field.name == "Header: Host" && field.value == "example.com")
        );
    }
}
