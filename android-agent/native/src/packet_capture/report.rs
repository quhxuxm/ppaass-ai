use super::*;

#[derive(Clone, Serialize)]
pub(super) struct CaptureReport {
    pub(super) exists: bool,
    pub(super) file_size: u64,
    pub(super) total_packets: usize,
    pub(super) packets: Vec<CapturedPacket>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct ReportCacheKey {
    pub(super) path: PathBuf,
    pub(super) file_size: u64,
    pub(super) modified: Option<SystemTime>,
    pub(super) limit: usize,
    pub(super) proxy_listen_port: Option<u16>,
}

pub(super) struct ReportCacheEntry {
    pub(super) key: ReportCacheKey,
    pub(super) report: CaptureReport,
}

pub(super) fn report_cache() -> &'static Mutex<Option<ReportCacheEntry>> {
    static CACHE: OnceLock<Mutex<Option<ReportCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

pub(super) fn invalidate_report_cache(path: &Path) {
    let mut cache = report_cache().lock();
    if cache.as_ref().is_some_and(|entry| entry.key.path == path) {
        *cache = None;
    }
}

#[derive(Clone, Serialize)]
pub(super) struct CapturedPacket {
    pub(super) number: usize,
    pub(super) timestamp_ms: u64,
    pub(super) direction: &'static str,
    pub(super) ip_version: u8,
    pub(super) protocol: String,
    pub(super) sub_protocol: Option<String>,
    pub(super) proxy_protocol: Option<String>,
    pub(super) source: String,
    pub(super) source_port: Option<u16>,
    pub(super) destination: String,
    pub(super) destination_port: Option<u16>,
    pub(super) length: usize,
    pub(super) summary: String,
    pub(super) payload_length: usize,
    pub(super) payload_preview_length: usize,
    pub(super) payload_truncated: bool,
    pub(super) payload_hex: String,
    pub(super) payload_text: String,
    pub(super) protocol_layers: Vec<ProtocolLayer>,
    #[serde(skip)]
    pub(super) tcp_sequence: Option<u32>,
    #[serde(skip)]
    pub(super) tcp_flags: Option<u8>,
    #[serde(skip)]
    pub(super) payload: Vec<u8>,
    #[serde(skip)]
    pub(super) analysis_payload_truncated: bool,
    #[serde(skip)]
    pub(super) proxy_marker: Option<ProxyPacketMarker>,
    #[serde(skip)]
    pub(super) legacy_proxy_session: Option<u64>,
    #[serde(skip)]
    pub(super) direction_tracked: bool,
}

#[derive(Clone, Serialize)]
pub(super) struct ProtocolLayer {
    pub(super) name: String,
    pub(super) summary: String,
    pub(super) fields: Vec<ProtocolField>,
}

#[derive(Clone, Serialize)]
pub(super) struct ProtocolField {
    pub(super) name: String,
    pub(super) value: String,
}

pub(super) fn read_report(
    path: &Path,
    limit: usize,
    proxy_listen_port: Option<u16>,
) -> Result<CaptureReport, String> {
    if !path.exists() {
        return Ok(CaptureReport {
            exists: false,
            file_size: 0,
            total_packets: 0,
            packets: Vec::new(),
        });
    }
    let file = File::open(path).map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    let file_size = metadata.len();
    let cache_key = ReportCacheKey {
        path: path.to_path_buf(),
        file_size,
        modified: metadata.modified().ok(),
        limit,
        proxy_listen_port,
    };
    if let Some(report) = report_cache()
        .lock()
        .as_ref()
        .filter(|entry| entry.key == cache_key)
        .map(|entry| entry.report.clone())
    {
        return Ok(report);
    }

    // A capture can be appended while this report is built. Take exactly the
    // number of bytes visible in the opened file's metadata snapshot so a
    // writer that is faster than the parser cannot keep this refresh alive
    // indefinitely. A record crossing the snapshot boundary is ignored.
    let mut reader = BufReader::new(file.take(file_size));
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
    let mut directions = WindowDirectionTracker::default();
    let mut proxy_flows = ProxyFlowTracker::new(proxy_listen_port);
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
            let key = flow_key(&packet);
            restrict_socks5_tcp_detection(&mut packet, proxy_listen_port);
            if let Some(marker) = packet.proxy_marker {
                packet.proxy_protocol = Some(marker.protocol.report_name().to_string());
                packet.direction = marker.direction.report_name();
            } else {
                if let Some(observation) = proxy_flows.observe(&packet, &key) {
                    packet.legacy_proxy_session = Some(observation.session_id);
                    packet.proxy_protocol = observation.protocol;
                }
                packet.direction =
                    if let Some(direction) = explicit_proxy_direction(&packet, proxy_listen_port) {
                        direction
                    } else {
                        packet.direction_tracked = true;
                        directions.observe(&packet, &key)
                    };
            }
            suppress_conflicting_socks5_detection(&mut packet);
            packets.push_back(packet);
            while packets.len() > limit {
                if let Some(discarded) = packets.pop_front()
                    && discarded.direction_tracked
                {
                    directions.release(&discarded, &flow_key(&discarded));
                }
            }
        }
    }
    let mut packets: Vec<_> = packets.into();
    for packet in &mut packets {
        if packet.proxy_protocol.is_none()
            && let Some(session_id) = packet.legacy_proxy_session
            && let Some(protocol) = proxy_flows.protocol_for_session(session_id)
        {
            packet.proxy_protocol = Some(protocol.to_string());
        }
    }
    reassemble_tcp(&mut packets);
    for packet in &mut packets {
        restrict_socks5_tcp_detection(packet, proxy_listen_port);
        suppress_conflicting_socks5_detection(packet);
        finalize_payload_preview(packet);
    }
    let report = CaptureReport {
        exists: true,
        file_size,
        total_packets,
        packets,
    };
    *report_cache().lock() = Some(ReportCacheEntry {
        key: cache_key,
        report: report.clone(),
    });
    Ok(report)
}
