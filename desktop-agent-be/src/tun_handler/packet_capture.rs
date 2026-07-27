//! Agent 双向明文包 PCAP 写入器。
//!
//! TUN 设备提供的是不含二层头的 IPv4/IPv6 包，因此使用 libpcap 的
//! DLT_RAW（101）。HTTP/SOCKS5 本地代理流量不经过 TUN，因此在本地入口把
//! 已传输的 TCP/UDP 字节封装成等价的原始 IP 包，和 TUN 包写入同一个文件。
//! 网络热路径只复制数据并尝试投递到有界队列，独立线程负责批量落盘；磁盘
//! 变慢时丢弃抓包副本，绝不反压代理流量。

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, IoSlice, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::task::{Context, Poll};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::{error, warn};

const PCAP_SNAPLEN: u32 = 65_535;
const PCAP_LINKTYPE_RAW: u32 = 101;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const MAX_SYNTHETIC_TCP_PAYLOAD: usize = PCAP_SNAPLEN as usize - IPV6_HEADER_LEN - TCP_HEADER_LEN;
const MAX_SYNTHETIC_UDP_PAYLOAD: usize = PCAP_SNAPLEN as usize - IPV6_HEADER_LEN - UDP_HEADER_LEN;
const CAPTURE_QUEUE_PACKETS: usize = 4_096;
const WRITER_BUFFER_BYTES: usize = 256 * 1024;
const WRITER_BATCH_PACKETS: usize = 512;
const WRITER_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone)]
pub struct PacketCaptureController {
    path: Arc<PathBuf>,
    active: Arc<ArcSwapOption<PacketCapture>>,
    transition: Arc<Mutex<()>>,
    synthetic_packet_id: Arc<AtomicU64>,
}

impl PacketCaptureController {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
            active: Arc::new(ArcSwapOption::empty()),
            transition: Arc::new(Mutex::new(())),
            synthetic_packet_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.active.load().is_some()
    }

    pub fn file(&self) -> &Path {
        self.path.as_path()
    }

    pub fn set_enabled(&self, enabled: bool) -> io::Result<()> {
        let _transition = self.transition.lock();
        if enabled == self.is_enabled() {
            return Ok(());
        }
        if enabled {
            self.active
                .store(Some(Arc::new(PacketCapture::open_or_append(&self.path)?)));
        } else {
            self.stop_active_writer();
        }
        Ok(())
    }

    pub fn clear(&self) -> io::Result<()> {
        let _transition = self.transition.lock();
        let was_enabled = self.is_enabled();
        self.stop_active_writer();
        let capture = PacketCapture::create(&self.path)?;
        if was_enabled {
            self.active.store(Some(Arc::new(capture)));
        }
        Ok(())
    }

    pub(super) fn record(&self, packet: &[u8]) -> io::Result<()> {
        let capture = self.active.load_full();
        match capture {
            Some(capture) => capture.record(packet),
            None => Ok(()),
        }
    }

    pub(crate) fn capture_tcp_stream(&self, stream: TcpStream) -> CapturedTcpStream {
        CapturedTcpStream::new(stream, self.clone())
    }

    pub(crate) fn record_udp_payload(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) {
        if payload.is_empty() || !self.is_enabled() {
            return;
        }
        let packet = synthetic_udp_packet(
            source,
            destination,
            &payload[..payload.len().min(MAX_SYNTHETIC_UDP_PAYLOAD)],
            self.next_synthetic_packet_id(),
        );
        if let Err(capture_error) = self.record(&packet) {
            warn!("SOCKS5 UDP 抓包副本写入失败：{capture_error}");
        }
    }

    fn next_synthetic_packet_id(&self) -> u16 {
        self.synthetic_packet_id.fetch_add(1, Ordering::Relaxed) as u16
    }

    fn stop_active_writer(&self) {
        let Some(capture) = self.active.swap(None) else {
            return;
        };
        while Arc::strong_count(&capture) > 1 {
            thread::yield_now();
        }
        drop(capture);
    }
}

pub(crate) struct CapturedTcpStream {
    inner: TcpStream,
    flow: Option<TcpCaptureFlow>,
}

impl CapturedTcpStream {
    fn new(inner: TcpStream, controller: PacketCaptureController) -> Self {
        let flow = inner
            .peer_addr()
            .ok()
            .zip(inner.local_addr().ok())
            .map(|(client, server)| TcpCaptureFlow {
                controller,
                client,
                server,
                client_sequence: 1,
                server_sequence: 1,
            });
        Self { inner, flow }
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
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
    controller: PacketCaptureController,
    client: SocketAddr,
    server: SocketAddr,
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
        if payload.is_empty() || !self.controller.is_enabled() {
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
            let packet = synthetic_tcp_packet(
                source,
                destination,
                sequence,
                acknowledgement,
                chunk,
                self.controller.next_synthetic_packet_id(),
            );
            if let Err(capture_error) = self.controller.record(&packet) {
                warn!("HTTP/SOCKS5 TCP 抓包副本写入失败：{capture_error}");
            }
            if client_to_server {
                self.client_sequence = self.client_sequence.wrapping_add(chunk.len() as u32);
            } else {
                self.server_sequence = self.server_sequence.wrapping_add(chunk.len() as u32);
            }
        }
    }
}

fn synthetic_tcp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgement: u32,
    payload: &[u8],
    packet_id: u16,
) -> Vec<u8> {
    let mut segment = vec![0u8; TCP_HEADER_LEN + payload.len()];
    segment[..2].copy_from_slice(&source.port().to_be_bytes());
    segment[2..4].copy_from_slice(&destination.port().to_be_bytes());
    segment[4..8].copy_from_slice(&sequence.to_be_bytes());
    segment[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    segment[12] = 5 << 4;
    segment[13] = 0x18; // PSH + ACK
    segment[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    segment[TCP_HEADER_LEN..].copy_from_slice(payload);
    finish_transport_packet(source, destination, 6, segment, 16, packet_id)
}

fn synthetic_udp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    packet_id: u16,
) -> Vec<u8> {
    let mut datagram = vec![0u8; UDP_HEADER_LEN + payload.len()];
    let datagram_len = datagram.len() as u16;
    datagram[..2].copy_from_slice(&source.port().to_be_bytes());
    datagram[2..4].copy_from_slice(&destination.port().to_be_bytes());
    datagram[4..6].copy_from_slice(&datagram_len.to_be_bytes());
    datagram[UDP_HEADER_LEN..].copy_from_slice(payload);
    finish_transport_packet(source, destination, 17, datagram, 6, packet_id)
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
            let pseudo_header = [
                source_ip.as_slice(),
                destination_ip.as_slice(),
                &[0, protocol],
                transport_len.as_slice(),
            ];
            let checksum = internet_checksum(
                &pseudo_header
                    .into_iter()
                    .chain(std::iter::once(transport.as_slice()))
                    .collect::<Vec<_>>(),
            );
            transport[checksum_offset..checksum_offset + 2]
                .copy_from_slice(&nonzero_udp_checksum(protocol, checksum).to_be_bytes());
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
            let pseudo_header = [
                source_octets.as_slice(),
                destination_octets.as_slice(),
                transport_len.as_slice(),
                &[0, 0, 0, protocol],
            ];
            let checksum = internet_checksum(
                &pseudo_header
                    .into_iter()
                    .chain(std::iter::once(transport.as_slice()))
                    .collect::<Vec<_>>(),
            );
            transport[checksum_offset..checksum_offset + 2]
                .copy_from_slice(&nonzero_udp_checksum(protocol, checksum).to_be_bytes());
            build_ipv6_packet(source_ip, destination_ip, protocol, &transport)
        }
    }
}

fn nonzero_udp_checksum(protocol: u8, checksum: u16) -> u16 {
    if protocol == 17 && checksum == 0 {
        u16::MAX
    } else {
        checksum
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

pub(super) struct PacketCapture {
    sender: Option<SyncSender<CaptureRecord>>,
    writer: Option<JoinHandle<()>>,
    dropped_packets: AtomicU64,
    disabled: AtomicBool,
}

impl PacketCapture {
    pub(super) fn create(path: &Path) -> io::Result<Self> {
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

    pub(super) fn open_or_append(path: &Path) -> io::Result<Self> {
        ensure_capture_parent(path)?;
        if let Some(file) = open_compatible_capture_for_append(path)? {
            return Self::start_writer(file);
        }
        Self::create(path)
    }

    fn start_writer(file: File) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(CAPTURE_QUEUE_PACKETS);
        let writer = thread::Builder::new()
            .name("ppaass-pcap-writer".to_string())
            .spawn(move || {
                if let Err(write_error) = writer_loop(file, receiver) {
                    error!("PCAP 后台写入线程退出：{write_error}");
                }
            })?;

        Ok(Self {
            sender: Some(sender),
            writer: Some(writer),
            dropped_packets: AtomicU64::new(0),
            disabled: AtomicBool::new(false),
        })
    }

    pub(super) fn record(&self, packet: &[u8]) -> io::Result<()> {
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

        let Some(sender) = &self.sender else {
            return Ok(());
        };
        match sender.try_send(record) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                let dropped = self.dropped_packets.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped.is_power_of_two() {
                    warn!(
                        dropped_packets = dropped,
                        "PCAP 写入队列已满，丢弃抓包副本以避免阻塞代理流量"
                    );
                }
                Ok(())
            }
            Err(TrySendError::Disconnected(_)) => {
                if !self.disabled.swap(true, Ordering::Relaxed) {
                    Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "PCAP 后台写入线程已退出",
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl Drop for PacketCapture {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(writer) = self.writer.take()
            && writer.join().is_err()
        {
            error!("PCAP 后台写入线程异常终止");
        }
        let dropped = self.dropped_packets.load(Ordering::Relaxed);
        if dropped > 0 {
            warn!(
                dropped_packets = dropped,
                "PCAP 抓包已停止，部分抓包副本因磁盘写入跟不上而被丢弃"
            );
        }
    }
}

fn writer_loop(file: File, receiver: Receiver<CaptureRecord>) -> io::Result<()> {
    let mut writer = BufWriter::with_capacity(WRITER_BUFFER_BYTES, file);
    let mut last_flush = Instant::now();

    loop {
        match receiver.recv_timeout(WRITER_FLUSH_INTERVAL) {
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
                if last_flush.elapsed() >= WRITER_FLUSH_INTERVAL {
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
    let mut header = [0u8; 16];
    header[..4].copy_from_slice(&record.seconds.to_le_bytes());
    header[4..8].copy_from_slice(&record.micros.to_le_bytes());
    header[8..12].copy_from_slice(&(record.packet.len() as u32).to_le_bytes());
    header[12..16].copy_from_slice(&record.original_len.to_le_bytes());
    writer.write_all(&header)?;
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
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut header = [0u8; 24];
    match file.read_exact(&mut header) {
        Ok(()) if header == global_header() => {}
        Ok(()) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "现有 PCAP 文件格式与当前抓包格式不兼容，请先备份或清空该文件",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "现有 PCAP 文件头不完整，请先备份或清空该文件",
            ));
        }
        Err(error) => return Err(error),
    }

    let file_len = file.metadata()?.len();
    let mut valid_end = 24u64;
    loop {
        file.seek(SeekFrom::Start(valid_end))?;
        let mut record_header = [0u8; 16];
        match file.read_exact(&mut record_header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error),
        }
        let captured_len =
            u32::from_le_bytes(record_header[8..12].try_into().expect("fixed PCAP header"));
        let original_len =
            u32::from_le_bytes(record_header[12..16].try_into().expect("fixed PCAP header"));
        if captured_len > PCAP_SNAPLEN || original_len < captured_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("PCAP 在偏移 {valid_end} 处包含无效记录，已保留原文件且未继续写入"),
            ));
        }
        let record_end = valid_end
            .checked_add(16)
            .and_then(|offset| offset.checked_add(u64::from(captured_len)))
            .unwrap_or(u64::MAX);
        if record_end > file_len {
            break;
        }
        valid_end = record_end;
    }

    if valid_end != file_len {
        warn!(
            path = %path.display(),
            original_bytes = file_len,
            repaired_bytes = valid_end,
            "PCAP 尾部存在未写完整的记录，续写前已截断残尾"
        );
        file.set_len(valid_end)?;
    }
    file.seek(SeekFrom::End(0))?;
    Ok(Some(file))
}

fn global_header() -> [u8; 24] {
    let mut header = [0u8; 24];
    header[..4].copy_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
    header[4..6].copy_from_slice(&2_u16.to_le_bytes());
    header[6..8].copy_from_slice(&4_u16.to_le_bytes());
    header[8..12].copy_from_slice(&0_i32.to_le_bytes());
    header[12..16].copy_from_slice(&0_u32.to_le_bytes());
    header[16..20].copy_from_slice(&PCAP_SNAPLEN.to_le_bytes());
    header[20..24].copy_from_slice(&PCAP_LINKTYPE_RAW.to_le_bytes());
    header
}

fn write_global_header(file: &mut File) -> io::Result<()> {
    file.write_all(&global_header())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn temporary_capture_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ppaass-{label}-{}-{}.pcap",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
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

    #[test]
    fn asynchronously_writes_raw_ip_pcap_header_and_packet() {
        let path = temporary_capture_path("packet-capture");
        let capture = PacketCapture::create(&path).unwrap();
        capture.record(&[0x45, 0, 0, 20]).unwrap();
        drop(capture);

        let bytes = fs::read(&path).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 101);
        assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(bytes[36..40].try_into().unwrap()), 4);
        assert_eq!(&bytes[40..], &[0x45, 0, 0, 20]);
    }

    #[test]
    fn full_queue_drops_capture_copy_without_blocking_or_error() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let capture = PacketCapture {
            sender: Some(sender),
            writer: None,
            dropped_packets: AtomicU64::new(0),
            disabled: AtomicBool::new(false),
        };

        capture.record(&[0x45]).unwrap();
        capture.record(&[0x45]).unwrap();

        assert_eq!(capture.dropped_packets.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn controller_defaults_off_and_can_toggle_and_clear_without_restart() {
        let path = temporary_capture_path("packet-capture-controller");
        let controller = PacketCaptureController::new(path.clone());

        assert!(!controller.is_enabled());
        controller.record(&[0x45, 0, 0, 20]).unwrap();
        assert!(!path.exists());

        controller.set_enabled(true).unwrap();
        assert!(controller.is_enabled());
        controller.record(&[0x45, 0, 0, 20]).unwrap();
        controller.clear().unwrap();
        assert!(controller.is_enabled());

        controller.set_enabled(false).unwrap();
        assert!(!controller.is_enabled());
        assert_eq!(fs::metadata(&path).unwrap().len(), 24);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn enabling_capture_appends_to_existing_pcap_until_explicitly_cleared() {
        let path = temporary_capture_path("packet-capture-append");
        let controller = PacketCaptureController::new(path.clone());

        controller.set_enabled(true).unwrap();
        controller.record(&[0x45, 0, 0, 20]).unwrap();
        controller.set_enabled(false).unwrap();
        let first_length = fs::metadata(&path).unwrap().len();

        controller.set_enabled(true).unwrap();
        controller.record(&[0x45, 0, 0, 20]).unwrap();
        controller.set_enabled(false).unwrap();

        let bytes = fs::read(&path).unwrap();
        assert!(bytes.len() as u64 > first_length);
        assert_eq!(read_pcap_packets(&bytes).len(), 2);

        controller.clear().unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 24);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn enabling_capture_repairs_an_incomplete_pcap_tail_before_appending() {
        let path = temporary_capture_path("packet-capture-repair-tail");
        let controller = PacketCaptureController::new(path.clone());

        controller.set_enabled(true).unwrap();
        controller.record(&[0x45, 0, 0, 20]).unwrap();
        controller.set_enabled(false).unwrap();

        let mut partial_record = [0u8; 19];
        partial_record[8..12].copy_from_slice(&10u32.to_le_bytes());
        partial_record[12..16].copy_from_slice(&10u32.to_le_bytes());
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&partial_record)
            .unwrap();

        controller.set_enabled(true).unwrap();
        controller.record(&[0x45, 0, 0, 21]).unwrap();
        controller.set_enabled(false).unwrap();

        let bytes = fs::read(&path).unwrap();
        let packets = read_pcap_packets(&bytes);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], [0x45, 0, 0, 20]);
        assert_eq!(packets[1], [0x45, 0, 0, 21]);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn enabling_capture_preserves_an_incompatible_existing_file() {
        let path = temporary_capture_path("packet-capture-incompatible");
        let original = b"not a compatible pcap";
        fs::write(&path, original).unwrap();
        let controller = PacketCaptureController::new(path.clone());

        let error = controller.set_enabled(true).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!controller.is_enabled());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn enabling_capture_preserves_a_structurally_invalid_record_and_following_data() {
        let path = temporary_capture_path("packet-capture-invalid-record");
        let mut original = global_header().to_vec();
        let mut invalid_record = [0u8; 16];
        invalid_record[8..12].copy_from_slice(&(PCAP_SNAPLEN + 1).to_le_bytes());
        invalid_record[12..16].copy_from_slice(&(PCAP_SNAPLEN + 1).to_le_bytes());
        original.extend_from_slice(&invalid_record);
        original.extend_from_slice(b"following data must remain");
        fs::write(&path, &original).unwrap();
        let controller = PacketCaptureController::new(path.clone());

        let error = controller.set_enabled(true).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!controller.is_enabled());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn synthetic_tcp_and_udp_packets_have_valid_headers_and_checksums() {
        let tcp_source: SocketAddr = "127.0.0.1:51000".parse().unwrap();
        let tcp_destination: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let tcp_packet = synthetic_tcp_packet(tcp_source, tcp_destination, 7, 11, b"GET", 42);
        assert_eq!(tcp_packet[0] >> 4, 4);
        assert_eq!(tcp_packet[9], 6);
        assert_eq!(
            u16::from_be_bytes(tcp_packet[2..4].try_into().unwrap()) as usize,
            tcp_packet.len()
        );
        assert_eq!(internet_checksum(&[&tcp_packet[..IPV4_HEADER_LEN]]), 0);
        let tcp = &tcp_packet[IPV4_HEADER_LEN..];
        let source_ip = [127, 0, 0, 1];
        let destination_ip = [127, 0, 0, 1];
        let tcp_len = (tcp.len() as u16).to_be_bytes();
        assert_eq!(
            internet_checksum(&[&source_ip, &destination_ip, &[0, 6], &tcp_len, tcp]),
            0
        );
        assert_eq!(u16::from_be_bytes(tcp[..2].try_into().unwrap()), 51000);
        assert_eq!(u16::from_be_bytes(tcp[2..4].try_into().unwrap()), 1080);
        assert_eq!(u32::from_be_bytes(tcp[4..8].try_into().unwrap()), 7);
        assert_eq!(tcp_payload(&tcp_packet), b"GET");

        let udp_source: SocketAddr = "[::1]:52000".parse().unwrap();
        let udp_destination: SocketAddr = "[::1]:53000".parse().unwrap();
        let udp_packet = synthetic_udp_packet(udp_source, udp_destination, b"dns", 43);
        assert_eq!(udp_packet[0] >> 4, 6);
        assert_eq!(udp_packet[6], 17);
        let udp = &udp_packet[IPV6_HEADER_LEN..];
        let source_ip = Ipv6Addr::LOCALHOST.octets();
        let destination_ip = Ipv6Addr::LOCALHOST.octets();
        let udp_len = (udp.len() as u32).to_be_bytes();
        assert_eq!(
            internet_checksum(&[&source_ip, &destination_ip, &udp_len, &[0, 0, 0, 17], udp]),
            0
        );
        assert_eq!(&udp[UDP_HEADER_LEN..], b"dns");
    }

    #[test]
    fn synthetic_tcp_capture_splits_large_payload_with_contiguous_sequences() {
        let path = temporary_capture_path("packet-capture-split");
        let controller = PacketCaptureController::new(path.clone());
        controller.set_enabled(true).unwrap();
        let mut flow = TcpCaptureFlow {
            controller: controller.clone(),
            client: "127.0.0.1:51000".parse().unwrap(),
            server: "127.0.0.1:1080".parse().unwrap(),
            client_sequence: 1,
            server_sequence: 1,
        };
        let payload = vec![0x5a; MAX_SYNTHETIC_TCP_PAYLOAD + 17];
        flow.record_client_to_server(&payload);
        controller.set_enabled(false).unwrap();

        let bytes = fs::read(&path).unwrap();
        let packets = read_pcap_packets(&bytes);
        assert_eq!(packets.len(), 2);
        let first_tcp = &packets[0][IPV4_HEADER_LEN..];
        let second_tcp = &packets[1][IPV4_HEADER_LEN..];
        assert_eq!(u32::from_be_bytes(first_tcp[4..8].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_be_bytes(second_tcp[4..8].try_into().unwrap()),
            1 + MAX_SYNTHETIC_TCP_PAYLOAD as u32
        );
        assert_eq!(tcp_payload(packets[0]).len(), MAX_SYNTHETIC_TCP_PAYLOAD);
        assert_eq!(tcp_payload(packets[1]).len(), 17);
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn captured_tcp_stream_records_both_directions_without_changing_io() {
        let path = temporary_capture_path("packet-capture-proxy-stream");
        let controller = PacketCaptureController::new(path.clone());
        controller.set_enabled(true).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut captured = controller.capture_tcp_stream(server);

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
        controller.set_enabled(false).unwrap();

        let bytes = fs::read(&path).unwrap();
        let packets = read_pcap_packets(&bytes);
        assert_eq!(packets.len(), 2);
        let first_tcp = &packets[0][IPV4_HEADER_LEN..];
        let second_tcp = &packets[1][IPV4_HEADER_LEN..];
        assert_eq!(
            u16::from_be_bytes(first_tcp[..2].try_into().unwrap()),
            client_addr.port()
        );
        assert_eq!(
            u16::from_be_bytes(first_tcp[2..4].try_into().unwrap()),
            listener_addr.port()
        );
        assert_eq!(tcp_payload(packets[0]), b"proxy request");
        assert_eq!(
            u16::from_be_bytes(second_tcp[..2].try_into().unwrap()),
            listener_addr.port()
        );
        assert_eq!(
            u16::from_be_bytes(second_tcp[2..4].try_into().unwrap()),
            client_addr.port()
        );
        assert_eq!(tcp_payload(packets[1]), b"proxy response");
        fs::remove_file(path).unwrap();
    }
}
