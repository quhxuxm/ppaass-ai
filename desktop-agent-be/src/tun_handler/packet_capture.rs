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

pub const PCAP_SNAPLEN: u32 = 65_535;

pub mod stream;
pub mod writer;

pub use stream::CapturedTcpStream;
pub use stream::{TcpCaptureFlow, internet_checksum, synthetic_tcp_packet, synthetic_udp_packet};
pub use writer::{PacketCapture, global_header};
const PCAP_LINKTYPE_RAW: u32 = 101;
pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;
pub const MAX_SYNTHETIC_TCP_PAYLOAD: usize =
    PCAP_SNAPLEN as usize - IPV6_HEADER_LEN - TCP_HEADER_LEN;
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

    pub fn record(&self, packet: &[u8]) -> io::Result<()> {
        let capture = self.active.load_full();
        match capture {
            Some(capture) => capture.record(packet),
            None => Ok(()),
        }
    }

    pub fn capture_tcp_stream(&self, stream: TcpStream) -> CapturedTcpStream {
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
