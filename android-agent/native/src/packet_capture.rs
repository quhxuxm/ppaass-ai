use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::fmt::{self, Write as FmtWrite};
use std::fs::{File, OpenOptions};
use std::io::{
    self, BufRead, BufReader, BufWriter, ErrorKind, IoSlice, Read, Seek, SeekFrom, Write,
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::warn;

const DLT_RAW: u32 = 101;
const PCAP_SNAPLEN: u32 = 65_535;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
const PROXY_CAPTURE_TCP_OPTION_LEN: usize = 8;
const SYNTHETIC_TCP_HEADER_LEN: usize = TCP_HEADER_LEN + PROXY_CAPTURE_TCP_OPTION_LEN;
const MAX_SYNTHETIC_TCP_PAYLOAD: usize = 16 * 1024;
const CAPTURE_QUEUE_PACKETS: usize = 1_024;
const WRITER_BATCH_PACKETS: usize = 512;
const FLUSH_INTERVAL: Duration = Duration::from_millis(250);
const APPEND_SCAN_BUFFER_BYTES: usize = 256 * 1024;
const MAX_RETURNED_PACKETS: usize = 2_000;
const PROXY_HANDSHAKE_PREFIX_LEN: usize = 16 * 1024;
const MAX_PACKET_ANALYSIS_BYTES: usize = 16 * 1024;
const MAX_PACKET_PAYLOAD_PREVIEW_BYTES: usize = 4 * 1024;
const MAX_REASSEMBLED_TCP_BYTES: usize = 512 * 1024;
const MAX_HTTP_START_LINE_BYTES: usize = 512;
const MAX_HTTP_HEADER_FIELDS: usize = 16;
const MAX_HTTP_HEADER_NAME_BYTES: usize = 64;
const MAX_HTTP_HEADER_VALUE_BYTES: usize = 256;
const MAX_PROXY_FLOW_STATES: usize = 2_048;
const MAX_PROXY_SESSION_LABELS: usize = 4_096;
const MAX_PROXY_PENDING_SEGMENTS: usize = 64;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
// RFC 6994 reserves TCP option kind 253 for experiments. The four-byte ExID
// keeps this app-local metadata distinguishable from other experiments. These
// synthetic packets exist only in the PCAP and are never transmitted.
const PROXY_CAPTURE_TCP_OPTION_KIND: u8 = 253;
const PROXY_CAPTURE_TCP_OPTION_EXPERIMENT_ID: [u8; 4] = *b"PAAS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProxyIngressProtocol {
    Http,
    Socks5,
}

impl ProxyIngressProtocol {
    fn marker_value(self) -> u8 {
        match self {
            Self::Http => 1,
            Self::Socks5 => 2,
        }
    }

    fn report_name(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Socks5 => "SOCKS5",
        }
    }

    fn from_marker(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Http),
            2 => Some(Self::Socks5),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyPacketDirection {
    Upload,
    Download,
}

impl ProxyPacketDirection {
    fn marker_value(self) -> u8 {
        match self {
            Self::Upload => 1,
            Self::Download => 2,
        }
    }

    fn report_name(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }

    fn from_marker(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Upload),
            2 => Some(Self::Download),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProxyPacketMarker {
    protocol: ProxyIngressProtocol,
    direction: ProxyPacketDirection,
}

struct CaptureRuntime {
    path: Mutex<Option<PathBuf>>,
    active: ArcSwapOption<PacketWriter>,
    transition: Mutex<()>,
    synthetic_packet_id: AtomicU64,
}

static RUNTIME: OnceLock<CaptureRuntime> = OnceLock::new();

fn runtime() -> &'static CaptureRuntime {
    RUNTIME.get_or_init(|| CaptureRuntime {
        path: Mutex::new(None),
        active: ArcSwapOption::empty(),
        transition: Mutex::new(()),
        synthetic_packet_id: AtomicU64::new(1),
    })
}

pub(crate) fn is_enabled() -> bool {
    runtime()
        .active
        .load_full()
        .is_some_and(|writer| writer.is_healthy())
}

pub(crate) fn set_enabled(path: PathBuf, enabled: bool) -> io::Result<()> {
    let state = runtime();
    let _transition = state.transition.lock();
    *state.path.lock() = Some(path.clone());
    let active = state.active.load_full();
    let has_active_writer = active.is_some();
    let has_healthy_writer = active.as_ref().is_some_and(|writer| writer.is_healthy());
    drop(active);
    if (enabled && has_healthy_writer) || (!enabled && !has_active_writer) {
        return Ok(());
    }
    if enabled {
        if has_active_writer {
            stop_writer(state);
        }
        state
            .active
            .store(Some(Arc::new(PacketWriter::open_or_append(&path)?)));
    } else {
        stop_writer(state);
    }
    Ok(())
}

pub(crate) fn clear(path: PathBuf) -> io::Result<()> {
    let state = runtime();
    let _transition = state.transition.lock();
    *state.path.lock() = Some(path.clone());
    let was_enabled = state
        .active
        .load_full()
        .is_some_and(|writer| writer.is_healthy());
    stop_writer(state);
    let writer = PacketWriter::create(&path)?;
    invalidate_report_cache(&path);
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

pub(crate) fn capture_tcp_stream(
    stream: TcpStream,
    protocol: ProxyIngressProtocol,
) -> CapturedTcpStream {
    CapturedTcpStream::new(stream, protocol)
}

pub(crate) fn report_json(
    path: &Path,
    limit: usize,
    proxy_listen_port: Option<u16>,
) -> Result<String, String> {
    let report = read_report(
        path,
        limit.clamp(1, MAX_RETURNED_PACKETS),
        proxy_listen_port,
    )?;
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

pub(crate) struct CapturedTcpStream {
    inner: TcpStream,
    flow: Option<TcpCaptureFlow>,
}

impl CapturedTcpStream {
    fn new(inner: TcpStream, protocol: ProxyIngressProtocol) -> Self {
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

struct TcpCaptureFlow {
    client: SocketAddr,
    server: SocketAddr,
    protocol: ProxyIngressProtocol,
    client_sequence: u32,
    server_sequence: u32,
}

impl TcpCaptureFlow {
    fn record_client_to_server(&mut self, payload: &[u8]) {
        self.record_payload(true, payload);
    }

    fn record_server_to_client(&mut self, payload: &[u8]) {
        self.record_payload(false, payload);
    }

    fn record_server_to_client_vectored(&mut self, payloads: &[IoSlice<'_>], written: usize) {
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

    fn record_payload(&mut self, client_to_server: bool, payload: &[u8]) {
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

fn synthetic_proxy_tcp_packet(
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

#[cfg(test)]
fn synthetic_tcp_packet(
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

#[cfg(test)]
fn synthetic_tcp_packet_with_flags(
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

fn finish_transport_packet(
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

fn socket_addr_to_ipv6(address: SocketAddr) -> Ipv6Addr {
    match address.ip() {
        std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        std::net::IpAddr::V6(ip) => ip,
    }
}

fn build_ipv4_packet(
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

fn build_ipv6_packet(
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

fn internet_checksum(parts: &[&[u8]]) -> u16 {
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
    health: Arc<WriterHealth>,
}

#[derive(Default)]
struct WriterHealth {
    failed: AtomicBool,
}

impl WriterHealth {
    fn is_healthy(&self) -> bool {
        !self.failed.load(Ordering::Acquire)
    }

    fn mark_failed(&self, error: impl fmt::Display) {
        if !self.failed.swap(true, Ordering::AcqRel) {
            warn!("Android PCAP writer stopped after an I/O failure: {error}");
        }
    }
}

impl PacketWriter {
    fn create(path: &Path) -> io::Result<Self> {
        ensure_capture_parent(path)?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        write_global_header(&mut file)?;
        file.flush()?;
        Self::start_writer(file)
    }

    fn open_or_append(path: &Path) -> io::Result<Self> {
        ensure_capture_parent(path)?;
        if let Some(file) = open_compatible_capture_for_append(path)? {
            return Self::start_writer(file);
        }
        Self::create(path)
    }

    fn start_writer(file: File) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(CAPTURE_QUEUE_PACKETS);
        let health = Arc::new(WriterHealth::default());
        let writer_health = health.clone();
        let writer = thread::Builder::new()
            .name("ppaass-android-pcap".to_string())
            .spawn(move || {
                if let Err(error) = writer_loop(file, receiver) {
                    writer_health.mark_failed(error);
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            writer: Some(writer),
            dropped_packets: AtomicU64::new(0),
            health,
        })
    }

    fn record(&self, packet: &[u8]) -> io::Result<()> {
        if !self.is_healthy() {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "capture writer is unhealthy",
            ));
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
                self.health
                    .mark_failed("capture writer channel disconnected");
                Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    "capture writer stopped",
                ))
            }
        }
    }

    fn is_healthy(&self) -> bool {
        self.health.is_healthy()
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

fn ensure_capture_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn open_compatible_capture_for_append(path: &Path) -> io::Result<Option<File>> {
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let file_len = file.metadata()?.len();
    let mut reader = BufReader::with_capacity(APPEND_SCAN_BUFFER_BYTES, file);
    let valid_end = scan_compatible_capture(&mut reader, file_len)?;
    let mut file = reader.into_inner();

    if valid_end != file_len {
        warn!(
            path = %path.display(),
            original_bytes = file_len,
            repaired_bytes = valid_end,
            "truncating an incomplete PCAP tail before appending"
        );
        file.set_len(valid_end)?;
    }
    file.seek(SeekFrom::End(0))?;
    Ok(Some(file))
}

fn scan_compatible_capture(reader: &mut impl BufRead, file_len: u64) -> io::Result<u64> {
    let mut header = [0u8; 24];
    match reader.read_exact(&mut header) {
        Ok(()) if header == global_header() => {}
        Ok(()) => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "existing PCAP is incompatible; back it up or clear it before capturing",
            ));
        }
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "existing PCAP header is incomplete; back it up or clear it before capturing",
            ));
        }
        Err(error) => return Err(error),
    }

    let mut valid_end = 24u64;
    loop {
        let mut record_header = [0u8; 16];
        match reader.read_exact(&mut record_header) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error),
        }
        let captured_len =
            u32::from_le_bytes(record_header[8..12].try_into().expect("fixed PCAP header"));
        let original_len =
            u32::from_le_bytes(record_header[12..16].try_into().expect("fixed PCAP header"));
        if captured_len > PCAP_SNAPLEN || original_len < captured_len {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "existing PCAP has an invalid record at offset {valid_end}; the file was preserved"
                ),
            ));
        }
        let record_end = valid_end
            .checked_add(16)
            .and_then(|offset| offset.checked_add(u64::from(captured_len)))
            .unwrap_or(u64::MAX);
        if record_end > file_len {
            break;
        }
        if !skip_buffered_exact(reader, usize::try_from(captured_len).unwrap_or(usize::MAX))? {
            break;
        }
        valid_end = record_end;
    }
    Ok(valid_end)
}

fn skip_buffered_exact(reader: &mut impl BufRead, mut remaining: usize) -> io::Result<bool> {
    while remaining > 0 {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(false);
        }
        let consumed = remaining.min(available.len());
        reader.consume(consumed);
        remaining -= consumed;
    }
    Ok(true)
}

fn global_header() -> [u8; 24] {
    let mut header = [0u8; 24];
    header[..4].copy_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
    header[4..6].copy_from_slice(&2_u16.to_le_bytes());
    header[6..8].copy_from_slice(&4_u16.to_le_bytes());
    header[8..12].copy_from_slice(&0_i32.to_le_bytes());
    header[12..16].copy_from_slice(&0_u32.to_le_bytes());
    header[16..20].copy_from_slice(&PCAP_SNAPLEN.to_le_bytes());
    header[20..24].copy_from_slice(&DLT_RAW.to_le_bytes());
    header
}

fn write_global_header(file: &mut File) -> io::Result<()> {
    file.write_all(&global_header())
}

#[derive(Clone, Serialize)]
struct CaptureReport {
    exists: bool,
    file_size: u64,
    total_packets: usize,
    packets: Vec<CapturedPacket>,
}

#[derive(Clone, PartialEq, Eq)]
struct ReportCacheKey {
    path: PathBuf,
    file_size: u64,
    modified: Option<SystemTime>,
    limit: usize,
    proxy_listen_port: Option<u16>,
}

struct ReportCacheEntry {
    key: ReportCacheKey,
    report: CaptureReport,
}

fn report_cache() -> &'static Mutex<Option<ReportCacheEntry>> {
    static CACHE: OnceLock<Mutex<Option<ReportCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

fn invalidate_report_cache(path: &Path) {
    let mut cache = report_cache().lock();
    if cache.as_ref().is_some_and(|entry| entry.key.path == path) {
        *cache = None;
    }
}

#[derive(Clone, Serialize)]
struct CapturedPacket {
    number: usize,
    timestamp_ms: u64,
    direction: &'static str,
    ip_version: u8,
    protocol: String,
    sub_protocol: Option<String>,
    proxy_protocol: Option<String>,
    source: String,
    source_port: Option<u16>,
    destination: String,
    destination_port: Option<u16>,
    length: usize,
    summary: String,
    payload_length: usize,
    payload_preview_length: usize,
    payload_truncated: bool,
    payload_hex: String,
    payload_text: String,
    protocol_layers: Vec<ProtocolLayer>,
    #[serde(skip)]
    tcp_sequence: Option<u32>,
    #[serde(skip)]
    tcp_flags: Option<u8>,
    #[serde(skip)]
    payload: Vec<u8>,
    #[serde(skip)]
    analysis_payload_truncated: bool,
    #[serde(skip)]
    proxy_marker: Option<ProxyPacketMarker>,
    #[serde(skip)]
    legacy_proxy_session: Option<u64>,
    #[serde(skip)]
    direction_tracked: bool,
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

fn read_report(
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
    let (
        protocol,
        source_port,
        destination_port,
        summary,
        payload,
        tcp_sequence,
        tcp_flags,
        mut transport_fields,
        proxy_marker,
    ) = match protocol_number {
        6 if transport.len() >= 20 => {
            let source_port = u16::from_be_bytes([transport[0], transport[1]]);
            let destination_port = u16::from_be_bytes([transport[2], transport[3]]);
            let header_len = usize::from(transport[12] >> 4) * 4;
            if !(TCP_HEADER_LEN..=transport.len()).contains(&header_len) {
                return None;
            }
            let flags = tcp_flags(transport[13]);
            let payload = &transport[header_len..];
            let proxy_marker =
                parse_proxy_capture_tcp_option(&transport[TCP_HEADER_LEN..header_len]);
            (
                "TCP".to_string(),
                Some(source_port),
                Some(destination_port),
                format!("{source_port} → {destination_port} [{flags}]"),
                payload,
                Some(u32::from_be_bytes(transport[4..8].try_into().unwrap())),
                Some(transport[13]),
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
                proxy_marker,
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
                None,
                vec![
                    field("Source port", source_port),
                    field("Destination port", destination_port),
                    field("Length", u16::from_be_bytes([transport[4], transport[5]])),
                    field("Payload length", format!("{} bytes", payload.len())),
                ],
                None,
            )
        }
        1 => (
            "ICMP".to_string(),
            None,
            None,
            format!("type {}", transport.first().copied().unwrap_or_default()),
            transport.get(8..).unwrap_or_default(),
            None,
            None,
            vec![
                field("Type", transport.first().copied().unwrap_or_default()),
                field("Code", transport.get(1).copied().unwrap_or_default()),
            ],
            None,
        ),
        58 => (
            "ICMPv6".to_string(),
            None,
            None,
            format!("type {}", transport.first().copied().unwrap_or_default()),
            transport.get(8..).unwrap_or_default(),
            None,
            None,
            vec![
                field("Type", transport.first().copied().unwrap_or_default()),
                field("Code", transport.get(1).copied().unwrap_or_default()),
            ],
            None,
        ),
        other => (
            format!("IP/{other}"),
            None,
            None,
            format!("IP protocol {other}"),
            transport,
            None,
            None,
            vec![field("Protocol number", other)],
            None,
        ),
    };
    if let Some(marker) = proxy_marker {
        transport_fields.push(field(
            "Explicit proxy ingress",
            marker.protocol.report_name(),
        ));
        transport_fields.push(field(
            "Explicit proxy direction",
            marker.direction.report_name(),
        ));
    }
    let payload_length = payload.len();
    let analysis_payload_length = payload_length.min(MAX_PACKET_ANALYSIS_BYTES);
    let analysis_payload = &payload[..analysis_payload_length];
    let analysis_payload_truncated = analysis_payload_length < payload_length;
    if analysis_payload_truncated {
        transport_fields.push(field(
            "Analyzed payload prefix",
            format!("{analysis_payload_length} of {payload_length} bytes"),
        ));
    }
    let application =
        analyze_application(&protocol, source_port, destination_port, analysis_payload);
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
        direction: proxy_marker
            .map(|marker| marker.direction.report_name())
            .unwrap_or("upload"),
        ip_version,
        protocol,
        sub_protocol,
        proxy_protocol: proxy_marker.map(|marker| marker.protocol.report_name().to_string()),
        source,
        source_port,
        destination,
        destination_port,
        length,
        summary,
        payload_length,
        payload_preview_length: 0,
        payload_truncated: false,
        payload_hex: String::new(),
        payload_text: String::new(),
        protocol_layers,
        tcp_sequence,
        tcp_flags,
        payload: analysis_payload.to_vec(),
        analysis_payload_truncated,
        proxy_marker,
        legacy_proxy_session: None,
        direction_tracked: false,
    })
}

fn parse_proxy_capture_tcp_option(options: &[u8]) -> Option<ProxyPacketMarker> {
    let mut offset = 0usize;
    while offset < options.len() {
        match options[offset] {
            0 => break,
            1 => offset += 1,
            kind => {
                let option_len = usize::from(*options.get(offset + 1)?);
                if option_len < 2 || offset + option_len > options.len() {
                    break;
                }
                let option = &options[offset..offset + option_len];
                if kind == PROXY_CAPTURE_TCP_OPTION_KIND
                    && option_len == PROXY_CAPTURE_TCP_OPTION_LEN
                    && option[2..6] == PROXY_CAPTURE_TCP_OPTION_EXPERIMENT_ID
                {
                    return Some(ProxyPacketMarker {
                        protocol: ProxyIngressProtocol::from_marker(option[6])?,
                        direction: ProxyPacketDirection::from_marker(option[7])?,
                    });
                }
                offset += option_len;
            }
        }
    }
    None
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
    if protocol == "TCP" && payload.first() == Some(&5) {
        return Some(analyze_socks5_tcp(payload));
    }
    analyze_http(payload)
}

fn analyze_http(payload: &[u8]) -> Option<ProtocolLayer> {
    let first_line_end = payload
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(payload.len());
    let first_line_bytes = payload[..first_line_end]
        .strip_suffix(b"\r")
        .unwrap_or(&payload[..first_line_end]);
    let is_response = first_line_bytes.starts_with(b"HTTP/");
    let is_request = [
        b"GET ".as_slice(),
        b"POST ".as_slice(),
        b"PUT ".as_slice(),
        b"PATCH ".as_slice(),
        b"DELETE ".as_slice(),
        b"HEAD ".as_slice(),
        b"OPTIONS ".as_slice(),
        b"CONNECT ".as_slice(),
        b"TRACE ".as_slice(),
    ]
    .iter()
    .any(|method| first_line_bytes.starts_with(method));
    if !is_response && !is_request {
        return None;
    }

    let first_line = bounded_lossy(first_line_bytes, MAX_HTTP_START_LINE_BYTES);
    let mut fields = vec![field("Start line", &first_line)];
    let parts: Vec<_> = first_line.split_whitespace().collect();
    if is_response {
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

    for line in payload
        .split(|byte| *byte == b'\n')
        .skip(1)
        .take(MAX_HTTP_HEADER_FIELDS)
    {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.iter().position(|byte| *byte == b':') {
            let name = bounded_lossy(&line[..colon], MAX_HTTP_HEADER_NAME_BYTES);
            let value = bounded_lossy(&line[colon + 1..], MAX_HTTP_HEADER_VALUE_BYTES);
            fields.push(field(
                format!("Header: {}", name.trim()),
                value.trim().to_string(),
            ));
        }
    }
    Some(layer("Hypertext Transfer Protocol", &first_line, fields))
}

fn bounded_lossy(bytes: &[u8], maximum_bytes: usize) -> String {
    let was_truncated = bytes.len() > maximum_bytes;
    let mut value = String::from_utf8_lossy(&bytes[..bytes.len().min(maximum_bytes)]).into_owned();
    if was_truncated {
        value.push('…');
    }
    value
}

fn analyze_socks5_tcp(payload: &[u8]) -> ProtocolLayer {
    let mut fields = vec![
        field("Version", 5),
        field("Captured length", format!("{} bytes", payload.len())),
    ];
    let summary = if payload.len() >= 4
        && payload[2] == 0
        && matches!(payload[1], 1..=3)
        && matches!(payload[3], 1 | 3 | 4)
    {
        let command = match payload[1] {
            1 => "CONNECT",
            2 => "BIND",
            3 => "UDP ASSOCIATE",
            _ => "Unknown",
        };
        let address_type = socks5_address_type(payload[3]);
        fields.push(field("Message type", "Command request"));
        fields.push(field("Command", command));
        fields.push(field("Address type", address_type));
        format!("{command} · {address_type}")
    } else if payload.len() >= 2 && payload[1] > 0 && payload.len() >= 2 + usize::from(payload[1]) {
        let method_count = payload[1];
        fields.push(field("Message type", "Authentication method negotiation"));
        fields.push(field("Method count", method_count));
        format!("{method_count} authentication method(s)")
    } else {
        let method_or_status = payload.get(1).copied().unwrap_or_default();
        fields.push(field("Message type", "Server response or partial message"));
        fields.push(field(
            "Method / status",
            format!("0x{method_or_status:02x}"),
        ));
        "Server response or partial message".to_string()
    };
    layer("SOCKS Version 5", summary, fields)
}

fn socks5_address_type(value: u8) -> &'static str {
    match value {
        1 => "IPv4",
        3 => "Domain",
        4 => "IPv6",
        _ => "Unknown",
    }
}

#[derive(Default)]
struct TcpReassemblySession {
    indices: Vec<usize>,
    syn_sequence: Option<u32>,
    last_payload_end_sequence: Option<u32>,
    has_payload: bool,
    closed: bool,
}

fn reassemble_tcp(packets: &mut [CapturedPacket]) {
    let mut streams = HashMap::<String, Vec<TcpReassemblySession>>::new();
    for (index, packet) in packets.iter().enumerate() {
        let Some(sequence) = packet.tcp_sequence else {
            continue;
        };
        let has_syn = tcp_has_flag(packet, TCP_FLAG_SYN);
        let has_terminal_flag =
            tcp_has_flag(packet, TCP_FLAG_FIN) || tcp_has_flag(packet, TCP_FLAG_RST);
        if packet.payload_length == 0 && !has_syn && !has_terminal_flag {
            continue;
        }

        let sessions = streams
            .entry(format!(
                "{}:{}>{}:{}",
                packet.source,
                packet.source_port.unwrap_or_default(),
                packet.destination,
                packet.destination_port.unwrap_or_default()
            ))
            .or_default();
        let starts_new_session = sessions.last().is_some_and(|session| {
            let exact_retransmission = session
                .indices
                .iter()
                .any(|prior| same_tcp_segment(&packets[*prior], packet));
            if has_syn && session.closed {
                true
            } else if has_syn || session.closed {
                !exact_retransmission
            } else {
                // Synthetic captures historically had no SYN/FIN. Sequence 1
                // is their sole backward-compatible session boundary; other
                // lower sequences are retransmission or out-of-order traffic.
                // Keep a natural 32-bit wrap only while 1 is the current
                // chronological continuation, rather than matching any stale
                // segment from earlier in the session.
                sequence == 1
                    && packet.payload_length > 0
                    && session.has_payload
                    && session.last_payload_end_sequence != Some(1)
            }
        });
        if sessions.is_empty() || starts_new_session {
            sessions.push(TcpReassemblySession {
                syn_sequence: has_syn.then_some(sequence),
                ..TcpReassemblySession::default()
            });
        }
        let session = sessions
            .last_mut()
            .expect("a TCP stream session was just created");
        if has_syn && session.syn_sequence.is_none() {
            session.syn_sequence = Some(sequence);
        }
        session.indices.push(index);
        session.has_payload |= packet.payload_length > 0;
        if packet.payload_length > 0 {
            session.last_payload_end_sequence = packet
                .tcp_sequence
                .map(|sequence| sequence.wrapping_add(tcp_sequence_span(packet)));
        }
        session.closed |= has_terminal_flag;
    }

    for session in streams.into_values().flatten() {
        reassemble_tcp_session(packets, session);
    }
}

fn reassemble_tcp_session(packets: &mut [CapturedPacket], session: TcpReassemblySession) {
    let mut payload_indices: Vec<_> = session
        .indices
        .iter()
        .copied()
        .filter(|index| packets[*index].payload_length > 0)
        .collect();
    if payload_indices.is_empty() {
        return;
    }
    let start = session
        .syn_sequence
        .map(|sequence| sequence.wrapping_add(1))
        .or_else(|| {
            payload_indices
                .iter()
                .filter_map(|index| tcp_payload_sequence(&packets[*index]))
                .reduce(|start, sequence| {
                    if (sequence.wrapping_sub(start) as i32) < 0 {
                        sequence
                    } else {
                        start
                    }
                })
        })
        .expect("payload packets have TCP sequence numbers");
    payload_indices.sort_by_key(|index| {
        tcp_payload_sequence(&packets[*index])
            .unwrap_or(start)
            .wrapping_sub(start)
    });

    let available_segment_count = payload_indices.len();
    let mut assembled = Vec::new();
    let mut contiguous_true_length = 0usize;
    let mut truncation_reason = None;
    let mut processed_count = 0usize;
    let mut last_processed = None;
    let mut diagnostic_terminal = payload_indices[0];
    for index in &payload_indices {
        let packet = &packets[*index];
        let sequence = tcp_payload_sequence(packet).unwrap_or(start);
        let offset = sequence.wrapping_sub(start) as usize;
        if offset > contiguous_true_length {
            diagnostic_terminal = last_processed.unwrap_or(*index);
            truncation_reason = Some(format!(
                "Sequence gap before packet {} (expected {}, received {})",
                packet.number,
                start.wrapping_add(contiguous_true_length as u32),
                sequence
            ));
            break;
        }

        let overlap = contiguous_true_length.saturating_sub(offset);
        if overlap >= packet.payload_length {
            processed_count += 1;
            last_processed = Some(last_processed.map_or(*index, |prior: usize| prior.max(*index)));
            continue;
        }
        let remaining_true_length = packet.payload_length - overlap;
        if overlap >= packet.payload.len() {
            diagnostic_terminal = last_processed.unwrap_or(*index);
            truncation_reason = Some(format!(
                "Packet {} payload is retained only as a bounded prefix",
                packet.number
            ));
            break;
        }
        let available = &packet.payload[overlap..];
        let append_length = available
            .len()
            .min(remaining_true_length)
            .min(MAX_REASSEMBLED_TCP_BYTES.saturating_sub(assembled.len()));
        assembled.extend_from_slice(&available[..append_length]);
        if append_length > 0 {
            processed_count += 1;
            last_processed = Some(last_processed.map_or(*index, |prior: usize| prior.max(*index)));
            diagnostic_terminal = last_processed.expect("the current packet was processed");
        }
        if append_length < remaining_true_length {
            truncation_reason = Some(if assembled.len() >= MAX_REASSEMBLED_TCP_BYTES {
                format!(
                    "Reassembly reached the {} byte analysis limit",
                    MAX_REASSEMBLED_TCP_BYTES
                )
            } else {
                format!(
                    "Packet {} payload is retained only as a bounded prefix",
                    packet.number
                )
            });
            break;
        }
        contiguous_true_length = contiguous_true_length.max(offset + packet.payload_length);
    }

    let is_truncated = truncation_reason.is_some();
    let terminal = if is_truncated {
        diagnostic_terminal
    } else {
        last_processed.unwrap_or(payload_indices[0])
    };
    if available_segment_count > 1 || is_truncated {
        let mut fields = vec![
            field("Captured payload segments", available_segment_count),
            field("Analyzed payload segments", processed_count),
            field("Sequence start", start),
        ];
        let summary = if let Some(reason) = truncation_reason {
            fields.push(field(
                "Analyzed prefix",
                format!("{} bytes", assembled.len()),
            ));
            fields.push(field("Reassembly truncated", true));
            fields.push(field("Truncation reason", reason));
            format!(
                "Analyzed prefix from {processed_count} of {available_segment_count} segments, {} bytes",
                assembled.len()
            )
        } else {
            fields.push(field(
                "Reassembled length",
                format!("{} bytes", assembled.len()),
            ));
            fields.push(field("Reassembly truncated", false));
            format!(
                "{available_segment_count} segments, {} bytes",
                assembled.len()
            )
        };
        packets[terminal]
            .protocol_layers
            .push(layer("Reassembled TCP Stream", summary, fields));

        if processed_count > 1
            && !assembled.is_empty()
            && let Some(mut application) = analyze_application(
                "TCP",
                packets[terminal].source_port,
                packets[terminal].destination_port,
                &assembled,
            )
        {
            packets[terminal].sub_protocol = Some(short_protocol(&application.name));
            application.summary = if is_truncated {
                format!(
                    "{} · analyzed reassembly prefix from {processed_count} of {available_segment_count} segments",
                    application.summary
                )
            } else {
                format!(
                    "{} · reassembled from {available_segment_count} segments",
                    application.summary
                )
            };
            packets[terminal].protocol_layers.push(application);
        }
    }
}

fn tcp_has_flag(packet: &CapturedPacket, flag: u8) -> bool {
    packet.tcp_flags.is_some_and(|flags| flags & flag != 0)
}

fn tcp_payload_sequence(packet: &CapturedPacket) -> Option<u32> {
    packet
        .tcp_sequence
        .map(|sequence| sequence.wrapping_add(u32::from(tcp_has_flag(packet, TCP_FLAG_SYN))))
}

fn tcp_sequence_span(packet: &CapturedPacket) -> u32 {
    (packet.payload_length as u32)
        .wrapping_add(u32::from(tcp_has_flag(packet, TCP_FLAG_SYN)))
        .wrapping_add(u32::from(tcp_has_flag(packet, TCP_FLAG_FIN)))
}

fn same_tcp_segment(left: &CapturedPacket, right: &CapturedPacket) -> bool {
    left.tcp_sequence == right.tcp_sequence
        && left
            .tcp_flags
            .map(|flags| flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST))
            == right
                .tcp_flags
                .map(|flags| flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST))
        && left.payload_length == right.payload_length
        && left.payload == right.payload
        && left.analysis_payload_truncated == right.analysis_payload_truncated
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
        "SOCKS Version 5" => "SOCKS5",
        value => value,
    }
    .to_string()
}

fn finalize_payload_preview(packet: &mut CapturedPacket) {
    let preview_length = packet.payload.len().min(MAX_PACKET_PAYLOAD_PREVIEW_BYTES);
    let preview = &packet.payload[..preview_length];
    packet.payload_preview_length = preview_length;
    packet.payload_truncated = preview_length < packet.payload_length;
    packet.payload_hex = hex(preview);
    packet.payload_text = ascii(preview);
    packet.payload.clear();
    packet.payload.shrink_to_fit();
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut output = String::with_capacity(bytes.len().saturating_mul(3).saturating_sub(1));
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn ascii(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len());
    for byte in bytes {
        output.push(if byte.is_ascii_graphic() || *byte == b' ' {
            char::from(*byte)
        } else {
            '.'
        });
    }
    output
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

fn explicit_proxy_direction(
    packet: &CapturedPacket,
    listen_port: Option<u16>,
) -> Option<&'static str> {
    let listen_port = listen_port?;
    if packet.protocol != "TCP" {
        return None;
    }
    if packet.destination_port == Some(listen_port) {
        Some("upload")
    } else if packet.source_port == Some(listen_port) {
        Some("download")
    } else {
        None
    }
}

#[derive(Default)]
struct WindowDirectionTracker {
    flows: HashMap<String, WindowDirectionState>,
}

struct WindowDirectionState {
    first_source: String,
    retained_packets: usize,
}

impl WindowDirectionTracker {
    fn observe(&mut self, packet: &CapturedPacket, flow_key: &str) -> &'static str {
        let source = endpoint(&packet.source, packet.source_port);
        let state =
            self.flows
                .entry(flow_key.to_string())
                .or_insert_with(|| WindowDirectionState {
                    first_source: source.clone(),
                    retained_packets: 0,
                });
        state.retained_packets += 1;
        if state.first_source == source {
            "upload"
        } else {
            "download"
        }
    }

    fn release(&mut self, packet: &CapturedPacket, flow_key: &str) {
        let should_remove = self.flows.get_mut(flow_key).is_some_and(|state| {
            state.retained_packets = state.retained_packets.saturating_sub(1);
            state.retained_packets == 0
        });
        if should_remove {
            self.flows.remove(flow_key);
        }
        debug_assert!(packet.direction_tracked);
    }
}

struct ProxyFlowState {
    session_id: u64,
    protocol: Option<String>,
    upload_prefix: Vec<u8>,
    upload_next_sequence: Option<u32>,
    upload_syn_sequence: Option<u32>,
    seen_packet: bool,
    seen_upload_payload: bool,
    upload_prefix_truncated: bool,
    pending_upload_segments: Vec<ProxyPendingSegment>,
    ended: bool,
}

#[derive(PartialEq, Eq)]
struct ProxyPendingSegment {
    sequence: u32,
    end_sequence: u32,
    payload_length: usize,
    payload_prefix: Vec<u8>,
}

impl ProxyFlowState {
    fn new(session_id: u64) -> Self {
        Self {
            session_id,
            protocol: None,
            upload_prefix: Vec::new(),
            upload_next_sequence: None,
            upload_syn_sequence: None,
            seen_packet: false,
            seen_upload_payload: false,
            upload_prefix_truncated: false,
            pending_upload_segments: Vec::new(),
            ended: false,
        }
    }
}

struct ProxyFlowObservation {
    session_id: u64,
    protocol: Option<String>,
}

struct ProxyFlowTracker {
    listen_port: Option<u16>,
    flows: HashMap<String, ProxyFlowState>,
    flow_order: VecDeque<String>,
    session_protocols: HashMap<u64, String>,
    session_order: VecDeque<u64>,
    next_session_id: u64,
}

impl ProxyFlowTracker {
    fn new(listen_port: Option<u16>) -> Self {
        Self {
            listen_port,
            flows: HashMap::new(),
            flow_order: VecDeque::new(),
            session_protocols: HashMap::new(),
            session_order: VecDeque::new(),
            next_session_id: 1,
        }
    }

    fn observe(&mut self, packet: &CapturedPacket, flow_key: &str) -> Option<ProxyFlowObservation> {
        let listen_port = self.listen_port?;
        if packet.protocol != "TCP" || !packet_uses_port(packet, listen_port) {
            return None;
        }

        if !self.flows.contains_key(flow_key) {
            self.insert_flow(flow_key);
        }
        let is_upload = packet.destination_port == Some(listen_port);
        let starts_new_session = {
            let state = self.flows.get(flow_key).expect("proxy flow was inserted");
            let new_syn = is_upload
                && tcp_has_flag(packet, TCP_FLAG_SYN)
                && state.seen_packet
                && (state.ended || state.upload_syn_sequence != packet.tcp_sequence);
            // Legacy synthetic captures have neither SYN/FIN nor network
            // retransmissions. Their upload sequence always starts at 1, so
            // another sequence-1 payload is an unconditional tuple-reuse
            // boundary unless the preceding segment naturally wrapped and
            // made 1 the expected continuation.
            let sequence_one_boundary = is_upload
                && packet.tcp_sequence == Some(1)
                && packet.payload_length > 0
                && state.seen_upload_payload
                && state.upload_next_sequence != Some(1);
            new_syn || sequence_one_boundary
        };
        if starts_new_session {
            let session_id = self.allocate_session_id();
            self.flows
                .insert(flow_key.to_string(), ProxyFlowState::new(session_id));
        }

        let state = self
            .flows
            .get_mut(flow_key)
            .expect("proxy flow was inserted");
        let mut stream_protocol = None;
        if is_upload && tcp_has_flag(packet, TCP_FLAG_SYN) {
            state.upload_syn_sequence = packet.tcp_sequence;
            if state.upload_next_sequence.is_none() {
                state.upload_next_sequence =
                    packet.tcp_sequence.map(|sequence| sequence.wrapping_add(1));
            }
        }
        if is_upload && packet.payload_length > 0 {
            append_proxy_upload_prefix(state, packet);
            state.seen_upload_payload = true;
            if state.protocol.is_none() {
                stream_protocol = detected_proxy_protocol_in_payload(packet, &state.upload_prefix);
            }
        }

        if state.protocol.is_none() {
            state.protocol = is_upload
                .then(|| detected_proxy_protocol(packet))
                .flatten()
                .or(stream_protocol)
                .map(str::to_string);
        }
        if state.protocol.is_some() {
            state.upload_prefix.clear();
            state.pending_upload_segments.clear();
        }
        state.seen_packet = true;
        state.ended |= tcp_has_flag(packet, TCP_FLAG_FIN) || tcp_has_flag(packet, TCP_FLAG_RST);
        let observation = ProxyFlowObservation {
            session_id: state.session_id,
            protocol: state.protocol.clone(),
        };
        let learned_protocol = state
            .protocol
            .as_ref()
            .map(|protocol| (state.session_id, protocol.clone()));
        if let Some((session_id, protocol)) = learned_protocol {
            self.remember_session_protocol(session_id, protocol);
        }
        Some(observation)
    }

    fn insert_flow(&mut self, flow_key: &str) {
        while self.flows.len() >= MAX_PROXY_FLOW_STATES {
            let Some(oldest) = self.flow_order.pop_front() else {
                break;
            };
            self.flows.remove(&oldest);
        }
        let session_id = self.allocate_session_id();
        self.flows
            .insert(flow_key.to_string(), ProxyFlowState::new(session_id));
        self.flow_order.push_back(flow_key.to_string());
    }

    fn allocate_session_id(&mut self) -> u64 {
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
        session_id
    }

    fn remember_session_protocol(&mut self, session_id: u64, protocol: String) {
        if self.session_protocols.contains_key(&session_id) {
            return;
        }
        while self.session_protocols.len() >= MAX_PROXY_SESSION_LABELS {
            let Some(oldest) = self.session_order.pop_front() else {
                break;
            };
            self.session_protocols.remove(&oldest);
        }
        self.session_protocols.insert(session_id, protocol);
        self.session_order.push_back(session_id);
    }

    fn protocol_for_session(&self, session_id: u64) -> Option<&str> {
        self.session_protocols.get(&session_id).map(String::as_str)
    }
}

fn append_proxy_upload_prefix(state: &mut ProxyFlowState, packet: &CapturedPacket) {
    if state.upload_prefix_truncated {
        return;
    }
    let Some(sequence) = tcp_payload_sequence(packet) else {
        return;
    };
    let segment = ProxyPendingSegment {
        sequence,
        end_sequence: packet
            .tcp_sequence
            .unwrap_or(sequence)
            .wrapping_add(tcp_sequence_span(packet)),
        payload_length: packet.payload_length,
        payload_prefix: packet.payload.clone(),
    };
    if !append_proxy_segment(state, &segment) {
        remember_pending_proxy_segment(state, segment);
        return;
    }
    drain_pending_proxy_segments(state);
}

fn append_proxy_segment(state: &mut ProxyFlowState, segment: &ProxyPendingSegment) -> bool {
    let append_from = match state.upload_next_sequence {
        None => 0,
        Some(expected) => {
            let relative = segment.sequence.wrapping_sub(expected) as i32;
            if relative > 0 {
                return false;
            }
            expected.wrapping_sub(segment.sequence) as usize
        }
    };
    if append_from >= segment.payload_length {
        if state
            .upload_next_sequence
            .is_some_and(|expected| segment.end_sequence.wrapping_sub(expected) as i32 > 0)
        {
            state.upload_next_sequence = Some(segment.end_sequence);
        }
        return true;
    }
    if append_from >= segment.payload_prefix.len() {
        state.upload_prefix_truncated = true;
        return true;
    }

    let true_remaining = segment.payload_length - append_from;
    let available = &segment.payload_prefix[append_from..];
    let append_length = available
        .len()
        .min(true_remaining)
        .min(PROXY_HANDSHAKE_PREFIX_LEN.saturating_sub(state.upload_prefix.len()));
    state
        .upload_prefix
        .extend_from_slice(&available[..append_length]);
    if append_length < true_remaining {
        state.upload_prefix_truncated = true;
    }
    state.upload_next_sequence = Some(segment.end_sequence);
    true
}

fn remember_pending_proxy_segment(state: &mut ProxyFlowState, segment: ProxyPendingSegment) {
    if state.pending_upload_segments.contains(&segment) {
        return;
    }
    let retained_bytes: usize = state
        .pending_upload_segments
        .iter()
        .map(|pending| pending.payload_prefix.len())
        .sum();
    if state.pending_upload_segments.len() >= MAX_PROXY_PENDING_SEGMENTS
        || retained_bytes.saturating_add(segment.payload_prefix.len()) > PROXY_HANDSHAKE_PREFIX_LEN
    {
        state.upload_prefix_truncated = true;
        state.pending_upload_segments.clear();
        return;
    }
    state.pending_upload_segments.push(segment);
}

fn drain_pending_proxy_segments(state: &mut ProxyFlowState) {
    while !state.upload_prefix_truncated {
        let Some(expected) = state.upload_next_sequence else {
            return;
        };
        state
            .pending_upload_segments
            .retain(|segment| segment.end_sequence.wrapping_sub(expected) as i32 > 0);
        let Some(index) = state
            .pending_upload_segments
            .iter()
            .position(|segment| segment.sequence.wrapping_sub(expected) as i32 <= 0)
        else {
            return;
        };
        let segment = state.pending_upload_segments.swap_remove(index);
        if !append_proxy_segment(state, &segment) {
            state.pending_upload_segments.push(segment);
            return;
        }
    }
}

fn packet_uses_port(packet: &CapturedPacket, port: u16) -> bool {
    packet.source_port == Some(port) || packet.destination_port == Some(port)
}

fn restrict_socks5_tcp_detection(packet: &mut CapturedPacket, listen_port: Option<u16>) {
    if packet.protocol != "TCP" || packet.sub_protocol.as_deref() != Some("SOCKS5") {
        return;
    }
    if packet.proxy_marker.is_some() {
        return;
    }
    if listen_port.is_some_and(|port| packet_uses_port(packet, port)) {
        return;
    }
    clear_socks5_detection(packet);
}

fn suppress_conflicting_socks5_detection(packet: &mut CapturedPacket) {
    if packet.sub_protocol.as_deref() == Some("SOCKS5")
        && packet
            .proxy_protocol
            .as_deref()
            .is_some_and(|protocol| protocol != "SOCKS5")
    {
        clear_socks5_detection(packet);
    }
}

fn clear_socks5_detection(packet: &mut CapturedPacket) {
    packet.sub_protocol = None;
    packet
        .protocol_layers
        .retain(|layer| layer.name != "SOCKS Version 5");
}

fn detected_proxy_protocol(packet: &CapturedPacket) -> Option<&str> {
    match packet.sub_protocol.as_deref() {
        Some(protocol @ ("HTTP" | "SOCKS5")) => Some(protocol),
        _ => None,
    }
}

fn detected_proxy_protocol_in_payload(
    packet: &CapturedPacket,
    payload: &[u8],
) -> Option<&'static str> {
    let layer = analyze_application("TCP", packet.source_port, packet.destination_port, payload)?;
    match layer.name.as_str() {
        "Hypertext Transfer Protocol" => Some("HTTP"),
        "SOCKS Version 5" => Some("SOCKS5"),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::io::Cursor;
    use std::rc::Rc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn capture_runtime_test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn temporary_capture_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ppaass-android-{label}-{}-{}.pcap",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn pcap_bytes(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = global_header().to_vec();
        for (index, packet) in packets.iter().enumerate() {
            bytes.extend_from_slice(&(index as u32 + 1).to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            bytes.extend_from_slice(packet);
        }
        bytes
    }

    fn read_pcap_packets(bytes: &[u8]) -> Vec<&[u8]> {
        let mut packets = Vec::new();
        let mut offset = 24usize;
        while offset + 16 <= bytes.len() {
            let captured_len =
                u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
            let packet_start = offset + 16;
            let packet_end = packet_start + captured_len;
            if packet_end > bytes.len() {
                break;
            }
            packets.push(&bytes[packet_start..packet_end]);
            offset = packet_end;
        }
        packets
    }

    fn tcp_payload(packet: &[u8]) -> &[u8] {
        let ip_header_len = match packet[0] >> 4 {
            4 => usize::from(packet[0] & 0x0f) * 4,
            6 => IPV6_HEADER_LEN,
            version => panic!("unexpected IP version {version}"),
        };
        let tcp = &packet[ip_header_len..];
        let tcp_header_len = usize::from(tcp[12] >> 4) * 4;
        &tcp[tcp_header_len..]
    }

    fn tcp_sequence(packet: &[u8]) -> u32 {
        let ip_header_len = match packet[0] >> 4 {
            4 => usize::from(packet[0] & 0x0f) * 4,
            6 => IPV6_HEADER_LEN,
            version => panic!("unexpected IP version {version}"),
        };
        u32::from_be_bytes(
            packet[ip_header_len + 4..ip_header_len + 8]
                .try_into()
                .unwrap(),
        )
    }

    fn report_for_packets(
        label: &str,
        packets: &[Vec<u8>],
        limit: usize,
        listen_port: Option<u16>,
    ) -> CaptureReport {
        let path = temporary_capture_path(label);
        fs::write(&path, pcap_bytes(packets)).unwrap();
        let report = read_report(&path, limit, listen_port).unwrap();
        fs::remove_file(path).unwrap();
        report
    }

    #[test]
    fn parses_http_connect_trace_and_socks5() {
        for request in [
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
            b"TRACE /debug HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
        ] {
            let layer = analyze_application("TCP", Some(50000), Some(18080), request).unwrap();
            assert_eq!(short_protocol(&layer.name), "HTTP");
            assert!(
                layer
                    .fields
                    .iter()
                    .any(|field| field.name == "Header: Host" && field.value == "example.com")
            );
        }

        let layer = analyze_application("TCP", Some(50000), Some(18080), &[5, 1, 0]).unwrap();
        assert_eq!(short_protocol(&layer.name), "SOCKS5");
        assert!(layer.summary.contains("authentication method"));

        let binary_post =
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nX-Obs: \x80\r\nContent-Length: 1\r\n\r\n\xff";
        let layer = analyze_application("TCP", Some(50000), Some(18080), binary_post).unwrap();
        assert_eq!(short_protocol(&layer.name), "HTTP");
        assert!(
            layer
                .fields
                .iter()
                .any(|field| field.name == "Method" && field.value == "POST")
        );
    }

    #[test]
    fn bounds_http_start_lines_and_header_values() {
        let mut request = b"GET /".to_vec();
        request.extend(std::iter::repeat_n(b'a', 64 * 1024));
        let layer = analyze_http(&request).expect("long request is still recognizable");
        assert!(layer.summary.chars().count() <= MAX_HTTP_START_LINE_BYTES + 1);
        let start_line = layer
            .fields
            .iter()
            .find(|field| field.name == "Start line")
            .expect("start line");
        assert!(start_line.value.chars().count() <= MAX_HTTP_START_LINE_BYTES + 1);

        let mut headers = b"GET / HTTP/1.1\r\nX-Long: ".to_vec();
        headers.extend(std::iter::repeat_n(b'b', 64 * 1024));
        headers.extend_from_slice(b"\r\n\r\n");
        let layer = analyze_http(&headers).expect("request with a long header");
        let value = layer
            .fields
            .iter()
            .find(|field| field.name == "Header: X-Long")
            .expect("bounded header value");
        assert!(value.value.chars().count() <= MAX_HTTP_HEADER_VALUE_BYTES + 1);
    }

    #[test]
    fn tcp_reassembly_uses_syn_boundaries_and_tolerates_reordering_and_retransmission() {
        let client: SocketAddr = "127.0.0.1:51010".parse().unwrap();
        let server: SocketAddr = "127.0.0.1:18081".parse().unwrap();
        let first = b"GET / HTTP/1.1\r\n";
        let second = b"Host: example.com\r\n\r\n";
        let first_sequence = 10_001;
        let second_sequence = first_sequence + first.len() as u32;
        let first_end = second_sequence + second.len() as u32;
        let packets = [
            synthetic_tcp_packet_with_flags(client, server, 10_000, 0, TCP_FLAG_SYN, b"", 1),
            // Later bytes arrive before the beginning of the request.
            synthetic_tcp_packet(client, server, second_sequence, 0, second, 2),
            synthetic_tcp_packet(client, server, first_sequence, 0, first, 3),
            // A retransmission must remain in the same session.
            synthetic_tcp_packet(client, server, first_sequence, 0, first, 4),
            synthetic_tcp_packet_with_flags(
                client,
                server,
                first_end,
                0,
                TCP_FLAG_FIN | 0x10,
                b"",
                5,
            ),
            // A fresh SYN with a higher ISN is an unconditional boundary.
            synthetic_tcp_packet_with_flags(client, server, 90_000, 0, TCP_FLAG_SYN, b"", 6),
            synthetic_tcp_packet(client, server, 90_001, 0, b"POST /next HTTP/1.1\r\n\r\n", 7),
        ];
        let report = report_for_packets("tcp-session-boundaries", &packets, packets.len(), None);
        let reassembly_layers: Vec<_> = report
            .packets
            .iter()
            .flat_map(|packet| &packet.protocol_layers)
            .filter(|layer| layer.name == "Reassembled TCP Stream")
            .collect();
        assert_eq!(reassembly_layers.len(), 1);
        assert!(
            report
                .packets
                .iter()
                .flat_map(|packet| &packet.protocol_layers)
                .any(|layer| layer.name == "Hypertext Transfer Protocol"
                    && layer.summary.contains("reassembled")
                    && layer.summary.starts_with("GET "))
        );
        assert!(
            report.packets.iter().any(|packet| {
                packet.tcp_sequence == Some(90_001)
                    && packet
                        .protocol_layers
                        .iter()
                        .all(|layer| layer.name != "Reassembled TCP Stream")
            }),
            "the post-SYN payload must not be joined to the prior connection"
        );
    }

    #[test]
    fn closed_tuple_reuse_with_identical_syn_and_payload_starts_a_new_session() {
        let client: SocketAddr = "127.0.0.1:51018".parse().unwrap();
        let server: SocketAddr = "127.0.0.1:18089".parse().unwrap();
        let request = b"GET /same HTTP/1.1\r\n\r\n";
        let end = 4_001 + request.len() as u32;
        let packets = [
            synthetic_tcp_packet_with_flags(client, server, 4_000, 0, TCP_FLAG_SYN, b"", 1),
            synthetic_tcp_packet(client, server, 4_001, 0, request, 2),
            synthetic_tcp_packet_with_flags(client, server, end, 0, TCP_FLAG_FIN | 0x10, b"", 3),
            synthetic_tcp_packet_with_flags(client, server, 4_000, 0, TCP_FLAG_SYN, b"", 4),
            synthetic_tcp_packet(client, server, 4_001, 0, request, 5),
        ];

        let report = report_for_packets(
            "closed-identical-tuple-reuse",
            &packets,
            packets.len(),
            None,
        );
        assert_eq!(
            report
                .packets
                .iter()
                .flat_map(|packet| &packet.protocol_layers)
                .filter(|layer| layer.name == "Reassembled TCP Stream")
                .count(),
            0,
            "identical packets from separate closed connections must not be reassembled together"
        );
    }

    #[test]
    fn syn_with_payload_and_fin_consume_tcp_sequence_space() {
        let client: SocketAddr = "127.0.0.1:51011".parse().unwrap();
        let server: SocketAddr = "127.0.0.1:18082".parse().unwrap();
        let packet = synthetic_tcp_packet_with_flags(
            client,
            server,
            4_000,
            0,
            TCP_FLAG_SYN | TCP_FLAG_FIN,
            b"abc",
            1,
        );
        let parsed = parse_ip_packet(1, 0, packet.len(), &packet).unwrap();
        assert_eq!(tcp_payload_sequence(&parsed), Some(4_001));
        assert_eq!(tcp_sequence_span(&parsed), 5);
    }

    #[test]
    fn legacy_sequence_one_is_the_only_payload_fallback_boundary() {
        let client: SocketAddr = "127.0.0.1:51012".parse().unwrap();
        let server: SocketAddr = "127.0.0.1:18083".parse().unwrap();
        let http = b"GET / HTTP/1.1\r\n\r\n";
        let packets = [
            synthetic_tcp_packet(client, server, 1, 0, http, 1),
            // Lower/out-of-order data other than sequence 1 is not a reset.
            synthetic_tcp_packet(client, server, 8, 0, &http[7..], 2),
            // A different sequence-1 payload is the legacy synthetic reset.
            synthetic_tcp_packet(client, server, 1, 0, &[5, 1, 0], 3),
        ];
        let report = report_for_packets("legacy-sequence-one", &packets, packets.len(), None);
        assert!(
            report.packets[2]
                .protocol_layers
                .iter()
                .all(|layer| layer.name != "Reassembled TCP Stream")
        );
    }

    #[test]
    fn legacy_identical_sequence_one_payload_resets_tracking_and_reassembly() {
        let client: SocketAddr = "127.0.0.1:51017".parse().unwrap();
        let proxy: SocketAddr = "127.0.0.1:18088".parse().unwrap();
        let greeting = [5, 1, 0];
        let request = [5, 1, 0, 1, 127, 0, 0, 1, 0, 80];
        let packets = [
            synthetic_tcp_packet(client, proxy, 1, 1, &greeting, 1),
            synthetic_tcp_packet(client, proxy, 4, 1, &request, 2),
            synthetic_tcp_packet(client, proxy, 1, 1, &greeting, 3),
            synthetic_tcp_packet(client, proxy, 4, 1, &request, 4),
        ];

        let parsed: Vec<_> = packets
            .iter()
            .enumerate()
            .map(|(index, packet)| {
                parse_ip_packet(index + 1, 0, packet.len(), packet).expect("synthetic TCP packet")
            })
            .collect();
        let key = flow_key(&parsed[0]);
        let mut tracker = ProxyFlowTracker::new(Some(proxy.port()));
        let sessions: Vec<_> = parsed
            .iter()
            .map(|packet| {
                tracker
                    .observe(packet, &key)
                    .expect("packet uses the proxy port")
                    .session_id
            })
            .collect();
        assert_eq!(sessions[0], sessions[1]);
        assert_ne!(sessions[1], sessions[2]);
        assert_eq!(sessions[2], sessions[3]);

        let report = report_for_packets(
            "legacy-identical-sequence-one",
            &packets,
            packets.len(),
            Some(proxy.port()),
        );
        let reassembled_sessions = report
            .packets
            .iter()
            .flat_map(|packet| &packet.protocol_layers)
            .filter(|layer| layer.name == "Reassembled TCP Stream")
            .count();
        assert_eq!(reassembled_sessions, 2);
        assert!(
            report
                .packets
                .iter()
                .all(|packet| packet.proxy_protocol.as_deref() == Some("SOCKS5"))
        );
    }

    #[test]
    fn packet_previews_and_reassembly_are_bounded_without_false_concatenation() {
        let client: SocketAddr = "127.0.0.1:51013".parse().unwrap();
        let server: SocketAddr = "127.0.0.1:18084".parse().unwrap();
        let large_payload = vec![b'x'; 48 * 1024];
        let next_payload = b"unrelated-tail";
        let packets = [
            synthetic_tcp_packet(client, server, 7_000, 0, &large_payload, 1),
            synthetic_tcp_packet(
                client,
                server,
                7_000 + large_payload.len() as u32,
                0,
                next_payload,
                2,
            ),
        ];
        let report = report_for_packets("bounded-payloads", &packets, packets.len(), None);
        let first = &report.packets[0];
        assert_eq!(first.payload_length, large_payload.len());
        assert_eq!(
            first.payload_preview_length,
            MAX_PACKET_PAYLOAD_PREVIEW_BYTES
        );
        assert!(first.payload_truncated);
        assert_eq!(first.payload_text.len(), MAX_PACKET_PAYLOAD_PREVIEW_BYTES);
        assert_eq!(
            first.payload_hex.len(),
            MAX_PACKET_PAYLOAD_PREVIEW_BYTES * 3 - 1
        );
        assert!(first.payload.is_empty());
        let reassembly = first
            .protocol_layers
            .iter()
            .find(|layer| layer.name == "Reassembled TCP Stream")
            .expect("truncated reassembly annotation");
        assert!(reassembly.summary.starts_with("Analyzed prefix"));
        assert!(
            reassembly
                .fields
                .iter()
                .any(|field| { field.name == "Reassembly truncated" && field.value == "true" })
        );
        assert!(
            report.packets[1]
                .protocol_layers
                .iter()
                .all(|layer| layer.name != "Reassembled TCP Stream"),
            "a segment after unavailable retained bytes must not be concatenated"
        );
    }

    #[test]
    fn retained_window_direction_state_is_bounded_and_stable() {
        let client: SocketAddr = "127.0.0.1:51014".parse().unwrap();
        let server: SocketAddr = "127.0.0.1:18085".parse().unwrap();
        let upload_bytes = synthetic_tcp_packet(client, server, 1, 0, b"a", 1);
        let download_bytes = synthetic_tcp_packet(server, client, 1, 0, b"b", 2);
        let mut upload =
            parse_ip_packet(1, 0, upload_bytes.len(), &upload_bytes).expect("upload packet");
        let mut download =
            parse_ip_packet(2, 0, download_bytes.len(), &download_bytes).expect("download packet");
        upload.direction_tracked = true;
        download.direction_tracked = true;
        let key = flow_key(&upload);
        let mut tracker = WindowDirectionTracker::default();
        assert_eq!(tracker.observe(&upload, &key), "upload");
        assert_eq!(tracker.observe(&download, &key), "download");
        tracker.release(&upload, &key);
        assert_eq!(tracker.observe(&upload, &key), "upload");
        tracker.release(&download, &key);
        tracker.release(&upload, &key);
        assert!(tracker.flows.is_empty());
    }

    #[test]
    fn report_ignores_a_record_crossing_its_file_snapshot() {
        let path = temporary_capture_path("partial-report-record");
        let client: SocketAddr = "127.0.0.1:51015".parse().unwrap();
        let server: SocketAddr = "127.0.0.1:18086".parse().unwrap();
        let packet = synthetic_tcp_packet(client, server, 1, 0, b"complete", 1);
        let mut bytes = pcap_bytes(&[packet]);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.extend_from_slice(b"partial");
        fs::write(&path, bytes).unwrap();

        let report = read_report(&path, 10, None).unwrap();
        assert_eq!(report.total_packets, 1);
        assert_eq!(report.packets.len(), 1);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn report_returns_while_the_capture_is_continuously_appended() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc as std_mpsc;

        let path = temporary_capture_path("live-report-snapshot");
        let client: SocketAddr = "127.0.0.1:51016".parse().unwrap();
        let server: SocketAddr = "127.0.0.1:18087".parse().unwrap();
        let packet = synthetic_tcp_packet(client, server, 1, 0, b"x", 1);
        let initial_packets = vec![packet.clone(); 20_000];
        fs::write(&path, pcap_bytes(&initial_packets)).unwrap();

        let keep_writing = Arc::new(AtomicBool::new(true));
        let writer_flag = keep_writing.clone();
        let writer_path = path.clone();
        let mut record = Vec::with_capacity(16 + packet.len());
        record.extend_from_slice(&1u32.to_le_bytes());
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        record.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        record.extend_from_slice(&packet);
        let batch = record.repeat(128);
        let writer = thread::spawn(move || {
            let mut file = OpenOptions::new().append(true).open(writer_path).unwrap();
            while writer_flag.load(Ordering::Relaxed) {
                file.write_all(&batch).unwrap();
                file.flush().unwrap();
                thread::sleep(Duration::from_millis(1));
            }
        });

        let (result_sender, result_receiver) = std_mpsc::channel();
        let reader_path = path.clone();
        let reader = thread::spawn(move || {
            let _ = result_sender.send(read_report(&reader_path, 10, None));
        });
        let result = result_receiver.recv_timeout(Duration::from_secs(5));
        keep_writing.store(false, Ordering::Relaxed);
        writer.join().unwrap();
        reader.join().unwrap();
        let report = result
            .expect("snapshot-bounded report must return while writes continue")
            .unwrap();
        assert!(fs::metadata(&path).unwrap().len() > report.file_size);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn proxy_protocol_survives_retention_and_segmented_handshakes() {
        let client: SocketAddr = "127.0.0.1:51000".parse().unwrap();
        let proxy: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let prefix = b"CONNE";
        let suffix = b"CT example.com:443 HTTP/1.1\r\n\r\n";
        let http = report_for_packets(
            "http-flow-label",
            &[
                synthetic_tcp_packet(client, proxy, 1, 1, prefix, 1),
                synthetic_tcp_packet(client, proxy, 1 + prefix.len() as u32, 1, suffix, 2),
                synthetic_tcp_packet(
                    proxy,
                    client,
                    1,
                    1 + (prefix.len() + suffix.len()) as u32,
                    &[22, 3, 3, 0, 1, 0],
                    3,
                ),
            ],
            3,
            Some(proxy.port()),
        );
        assert_eq!(http.packets.len(), 3);
        assert!(
            http.packets
                .iter()
                .all(|packet| packet.proxy_protocol.as_deref() == Some("HTTP"))
        );
        assert_eq!(http.packets[0].direction, "upload");
        assert_eq!(http.packets[2].direction, "download");

        let socks = report_for_packets(
            "socks-flow-label",
            &[
                synthetic_tcp_packet(client, proxy, 1, 1, &[5, 1, 0], 1),
                synthetic_tcp_packet(proxy, client, 1, 4, &[22, 3, 3, 0, 1, 0], 2),
            ],
            1,
            Some(proxy.port()),
        );
        assert_eq!(socks.packets.len(), 1);
        assert_eq!(socks.packets[0].proxy_protocol.as_deref(), Some("SOCKS5"));
        assert_eq!(socks.packets[0].direction, "download");
    }

    #[test]
    fn legacy_proxy_tracking_handles_out_of_order_handshakes_and_sequence_wrap() {
        let client: SocketAddr = "127.0.0.1:51001".parse().unwrap();
        let proxy: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let out_of_order = report_for_packets(
            "legacy-out-of-order-handshake",
            &[
                synthetic_tcp_packet_with_flags(client, proxy, 1_000, 0, TCP_FLAG_SYN, b"", 1),
                synthetic_tcp_packet(client, proxy, 1_006, 0, b"CT / HTTP/1.1\r\n\r\n", 2),
                synthetic_tcp_packet(client, proxy, 1_001, 0, b"CONNE", 3),
            ],
            3,
            Some(proxy.port()),
        );
        assert!(
            out_of_order
                .packets
                .iter()
                .all(|packet| packet.proxy_protocol.as_deref() == Some("HTTP"))
        );

        let wrapped = report_for_packets(
            "legacy-sequence-wrap",
            &[
                synthetic_tcp_packet(client, proxy, u32::MAX - 2, 0, b"CONN", 1),
                synthetic_tcp_packet(client, proxy, 1, 0, b"ECT / HTTP/1.1\r\n\r\n", 2),
            ],
            2,
            Some(proxy.port()),
        );
        assert!(
            wrapped
                .packets
                .iter()
                .all(|packet| packet.proxy_protocol.as_deref() == Some("HTTP"))
        );
    }

    #[test]
    fn legacy_sequence_wrap_is_only_a_boundary_while_one_is_expected() {
        let client: SocketAddr = "127.0.0.1:51019".parse().unwrap();
        let proxy: SocketAddr = "127.0.0.1:18091".parse().unwrap();
        let suffix = b"ECT / HTTP/1.1\r\n\r\n";
        let packets = [
            synthetic_tcp_packet(client, proxy, u32::MAX - 2, 0, b"CONN", 1),
            synthetic_tcp_packet(client, proxy, 1, 0, suffix, 2),
            synthetic_tcp_packet(client, proxy, 1, 0, suffix, 3),
        ];
        let report = report_for_packets(
            "legacy-current-sequence-wrap",
            &packets,
            packets.len(),
            Some(proxy.port()),
        );

        assert_eq!(report.packets[0].proxy_protocol.as_deref(), Some("HTTP"));
        assert_eq!(report.packets[1].proxy_protocol.as_deref(), Some("HTTP"));
        assert_eq!(report.packets[2].proxy_protocol, None);
        assert!(
            report.packets[1]
                .protocol_layers
                .iter()
                .any(|layer| layer.name == "Reassembled TCP Stream")
        );
        assert!(
            report.packets[1]
                .protocol_layers
                .iter()
                .any(|layer| layer.name == "Hypertext Transfer Protocol"
                    && layer.summary.contains("reassembled"))
        );
        assert!(
            report.packets[2]
                .protocol_layers
                .iter()
                .all(|layer| layer.name != "Reassembled TCP Stream")
        );
    }

    #[test]
    fn embedded_proxy_markers_survive_port_changes_and_mid_tunnel_payloads() {
        let client: SocketAddr = "127.0.0.1:51000".parse().unwrap();
        let proxy: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let packets = [
            synthetic_proxy_tcp_packet(
                client,
                proxy,
                9_000,
                7_000,
                &[22, 3, 3, 0, 1, 0],
                1,
                ProxyPacketMarker {
                    protocol: ProxyIngressProtocol::Http,
                    direction: ProxyPacketDirection::Upload,
                },
            ),
            synthetic_proxy_tcp_packet(
                proxy,
                client,
                7_000,
                9_006,
                b"GET /inside-socks HTTP/1.1\r\n\r\n",
                2,
                ProxyPacketMarker {
                    protocol: ProxyIngressProtocol::Socks5,
                    direction: ProxyPacketDirection::Download,
                },
            ),
        ];

        let report = report_for_packets("marked-proxy", &packets, 2, Some(19090));

        assert_eq!(report.packets[0].proxy_protocol.as_deref(), Some("HTTP"));
        assert_eq!(report.packets[0].direction, "upload");
        assert_eq!(report.packets[1].proxy_protocol.as_deref(), Some("SOCKS5"));
        assert_eq!(report.packets[1].direction, "download");
        assert_eq!(report.packets[1].sub_protocol.as_deref(), Some("HTTP"));
    }

    #[test]
    fn proxy_protocol_is_port_scoped_and_resets_on_tuple_reuse() {
        let client: SocketAddr = "127.0.0.1:51000".parse().unwrap();
        let proxy: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let unrelated_http: SocketAddr = "203.0.113.10:80".parse().unwrap();
        let unrelated_tls: SocketAddr = "203.0.113.20:443".parse().unwrap();
        let unrelated = report_for_packets(
            "unrelated-protocols",
            &[
                synthetic_tcp_packet(client, unrelated_http, 1, 1, b"GET / HTTP/1.1\r\n\r\n", 1),
                synthetic_tcp_packet(client, unrelated_tls, 1, 1, &[5, 1, 0], 2),
            ],
            2,
            Some(proxy.port()),
        );
        assert!(
            unrelated
                .packets
                .iter()
                .all(|packet| packet.proxy_protocol.is_none())
        );
        assert_ne!(unrelated.packets[1].sub_protocol.as_deref(), Some("SOCKS5"));

        let http_request = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        let reused = report_for_packets(
            "tuple-reuse",
            &[
                synthetic_tcp_packet(client, proxy, 1, 1, http_request, 1),
                synthetic_tcp_packet(
                    client,
                    proxy,
                    1 + http_request.len() as u32,
                    1,
                    &[22, 3, 3, 0, 1, 0],
                    2,
                ),
                synthetic_tcp_packet(client, proxy, 1, 1, &[5, 1, 0], 3),
                synthetic_tcp_packet(proxy, client, 1, 4, &[5, 0], 4),
            ],
            4,
            Some(proxy.port()),
        );
        assert_eq!(reused.packets[1].proxy_protocol.as_deref(), Some("HTTP"));
        assert_eq!(reused.packets[2].proxy_protocol.as_deref(), Some("SOCKS5"));
        assert_eq!(reused.packets[3].proxy_protocol.as_deref(), Some("SOCKS5"));
    }

    #[test]
    fn reopening_capture_appends_repairs_tail_and_preserves_incompatible_files() {
        let path = temporary_capture_path("append");
        let first = PacketWriter::open_or_append(&path).unwrap();
        first.record(&[0x45, 0, 0, 20]).unwrap();
        drop(first);
        let first_len = fs::metadata(&path).unwrap().len();

        let mut partial_record = [0u8; 19];
        partial_record[8..12].copy_from_slice(&10u32.to_le_bytes());
        partial_record[12..16].copy_from_slice(&10u32.to_le_bytes());
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&partial_record)
            .unwrap();

        let second = PacketWriter::open_or_append(&path).unwrap();
        second.record(&[0x45, 0, 0, 21]).unwrap();
        drop(second);
        let bytes = fs::read(&path).unwrap();
        assert!(bytes.len() as u64 > first_len);
        let packets = read_pcap_packets(&bytes);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], [0x45, 0, 0, 20]);
        assert_eq!(packets[1], [0x45, 0, 0, 21]);
        fs::remove_file(path).unwrap();

        let incompatible_path = temporary_capture_path("incompatible");
        let incompatible = b"not a compatible pcap";
        fs::write(&incompatible_path, incompatible).unwrap();
        let error = match PacketWriter::open_or_append(&incompatible_path) {
            Ok(_) => panic!("incompatible PCAP must not be overwritten"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(fs::read(&incompatible_path).unwrap(), incompatible);
        fs::remove_file(incompatible_path).unwrap();
    }

    #[test]
    fn append_validation_scans_many_records_through_a_bounded_number_of_reads() {
        struct CountingReader {
            inner: Cursor<Vec<u8>>,
            reads: Rc<Cell<usize>>,
        }

        impl Read for CountingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.reads.set(self.reads.get() + 1);
                Read::read(&mut self.inner, buffer)
            }
        }

        let packet = [0x45u8; 32];
        let record_count = 20_000u32;
        let mut bytes = global_header().to_vec();
        for index in 0..record_count {
            bytes.extend_from_slice(&index.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&packet);
        }
        let expected_len = bytes.len() as u64;
        let reads = Rc::new(Cell::new(0));
        let counting = CountingReader {
            inner: Cursor::new(bytes),
            reads: reads.clone(),
        };
        let mut reader = BufReader::with_capacity(64 * 1024, counting);

        assert_eq!(
            scan_compatible_capture(&mut reader, expected_len).unwrap(),
            expected_len
        );
        assert!(
            reads.get() < 64,
            "buffered scan used {} reads for {record_count} records",
            reads.get()
        );
    }

    #[test]
    fn disabled_capture_bytes_advance_synthetic_tcp_sequence() {
        let _guard = capture_runtime_test_lock().blocking_lock();
        let path = temporary_capture_path("capture-toggle-gap");
        set_enabled(path.clone(), false).unwrap();
        set_enabled(path.clone(), true).unwrap();
        let mut flow = TcpCaptureFlow {
            client: "127.0.0.1:51000".parse().unwrap(),
            server: "127.0.0.1:18080".parse().unwrap(),
            protocol: ProxyIngressProtocol::Http,
            client_sequence: 1,
            server_sequence: 1,
        };

        flow.record_client_to_server(b"before");
        set_enabled(path.clone(), false).unwrap();
        flow.record_client_to_server(b"not-captured");
        set_enabled(path.clone(), true).unwrap();
        flow.record_client_to_server(b"after");
        set_enabled(path.clone(), false).unwrap();

        let bytes = fs::read(&path).unwrap();
        let packets = read_pcap_packets(&bytes);
        let before = packets
            .iter()
            .copied()
            .find(|packet| tcp_payload(packet) == b"before")
            .unwrap();
        let after = packets
            .iter()
            .copied()
            .find(|packet| tcp_payload(packet) == b"after")
            .unwrap();
        assert_eq!(tcp_sequence(before), 1);
        assert_eq!(
            tcp_sequence(after),
            1 + b"before".len() as u32 + b"not-captured".len() as u32
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn synthetic_proxy_payloads_are_split_into_bounded_marked_packets() {
        let _guard = capture_runtime_test_lock().blocking_lock();
        let path = temporary_capture_path("bounded-synthetic-packets");
        set_enabled(path.clone(), false).unwrap();
        set_enabled(path.clone(), true).unwrap();
        let mut flow = TcpCaptureFlow {
            client: "127.0.0.1:51020".parse().unwrap(),
            server: "127.0.0.1:18090".parse().unwrap(),
            protocol: ProxyIngressProtocol::Socks5,
            client_sequence: 1,
            server_sequence: 1,
        };
        let payload = vec![b'z'; MAX_SYNTHETIC_TCP_PAYLOAD + 17];
        flow.record_client_to_server(&payload);
        set_enabled(path.clone(), false).unwrap();

        let bytes = fs::read(&path).unwrap();
        let packets = read_pcap_packets(&bytes);
        assert_eq!(CAPTURE_QUEUE_PACKETS, 1_024);
        assert_eq!(packets.len(), 2);
        assert_eq!(tcp_payload(packets[0]).len(), MAX_SYNTHETIC_TCP_PAYLOAD);
        assert_eq!(tcp_payload(packets[1]).len(), 17);
        assert_eq!(tcp_sequence(packets[0]), 1);
        assert_eq!(
            tcp_sequence(packets[1]),
            1 + MAX_SYNTHETIC_TCP_PAYLOAD as u32
        );
        for packet in packets {
            let parsed = parse_ip_packet(1, 0, packet.len(), packet).unwrap();
            assert_eq!(
                parsed.proxy_marker,
                Some(ProxyPacketMarker {
                    protocol: ProxyIngressProtocol::Socks5,
                    direction: ProxyPacketDirection::Upload,
                })
            );
            assert!(!tcp_has_flag(&parsed, TCP_FLAG_SYN));
            assert!(!tcp_has_flag(&parsed, TCP_FLAG_FIN));
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_writer_is_not_enabled_and_can_be_replaced() {
        let _guard = capture_runtime_test_lock().blocking_lock();
        let path = temporary_capture_path("failed-writer-replacement");
        set_enabled(path.clone(), false).unwrap();
        set_enabled(path.clone(), true).unwrap();
        let failed_health = runtime()
            .active
            .load_full()
            .expect("active writer")
            .health
            .clone();
        failed_health.mark_failed("injected test failure");
        assert!(!is_enabled());

        set_enabled(path.clone(), true).unwrap();
        let replacement_health = runtime()
            .active
            .load_full()
            .expect("replacement writer")
            .health
            .clone();
        assert!(replacement_health.is_healthy());
        assert!(!Arc::ptr_eq(&failed_health, &replacement_health));

        record(&[0x45, 0, 0, 20]);
        set_enabled(path.clone(), false).unwrap();
        assert_eq!(read_pcap_packets(&fs::read(&path).unwrap()).len(), 1);
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn captured_tcp_stream_records_both_directions_without_changing_io() {
        let _guard = capture_runtime_test_lock().lock().await;
        let path = temporary_capture_path("proxy-stream");
        set_enabled(path.clone(), false).unwrap();
        set_enabled(path.clone(), true).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut captured = capture_tcp_stream(server, ProxyIngressProtocol::Http);

        client.write_all(b"proxy request").await.unwrap();
        let mut request = [0u8; 13];
        captured.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"proxy request");

        captured.write_all(b"proxy response").await.unwrap();
        let mut response = [0u8; 14];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"proxy response");

        drop(captured);
        drop(client);
        set_enabled(path.clone(), false).unwrap();

        let bytes = fs::read(&path).unwrap();
        let packets = read_pcap_packets(&bytes);
        let request_packet = packets
            .iter()
            .copied()
            .find(|packet| tcp_payload(packet) == b"proxy request")
            .expect("captured request");
        let response_packet = packets
            .iter()
            .copied()
            .find(|packet| tcp_payload(packet) == b"proxy response")
            .expect("captured response");
        let first_tcp = &request_packet[IPV4_HEADER_LEN..];
        let second_tcp = &response_packet[IPV4_HEADER_LEN..];
        assert_eq!(
            u16::from_be_bytes(first_tcp[..2].try_into().unwrap()),
            client_addr.port()
        );
        assert_eq!(
            u16::from_be_bytes(first_tcp[2..4].try_into().unwrap()),
            listener_addr.port()
        );
        assert_eq!(tcp_payload(request_packet), b"proxy request");
        assert_eq!(
            u16::from_be_bytes(second_tcp[..2].try_into().unwrap()),
            listener_addr.port()
        );
        assert_eq!(
            u16::from_be_bytes(second_tcp[2..4].try_into().unwrap()),
            client_addr.port()
        );
        assert_eq!(tcp_payload(response_packet), b"proxy response");
        let report = read_report(&path, 10, None).unwrap();
        let captured_packets: Vec<_> = report
            .packets
            .iter()
            .filter(|packet| {
                packet.payload_text.contains("proxy request")
                    || packet.payload_text.contains("proxy response")
            })
            .collect();
        assert_eq!(captured_packets.len(), 2);
        assert_eq!(captured_packets[0].proxy_protocol.as_deref(), Some("HTTP"));
        assert_eq!(captured_packets[0].direction, "upload");
        assert_eq!(captured_packets[1].proxy_protocol.as_deref(), Some("HTTP"));
        assert_eq!(captured_packets[1].direction, "download");
        fs::remove_file(path).unwrap();
    }
}
