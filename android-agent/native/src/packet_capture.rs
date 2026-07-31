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
pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
const PROXY_CAPTURE_TCP_OPTION_LEN: usize = 8;
const SYNTHETIC_TCP_HEADER_LEN: usize = TCP_HEADER_LEN + PROXY_CAPTURE_TCP_OPTION_LEN;
pub const MAX_SYNTHETIC_TCP_PAYLOAD: usize = 16 * 1024;
pub const CAPTURE_QUEUE_PACKETS: usize = 1_024;
const WRITER_BATCH_PACKETS: usize = 512;
const FLUSH_INTERVAL: Duration = Duration::from_millis(250);
const APPEND_SCAN_BUFFER_BYTES: usize = 256 * 1024;
const MAX_RETURNED_PACKETS: usize = 2_000;
const PROXY_HANDSHAKE_PREFIX_LEN: usize = 16 * 1024;
const MAX_PACKET_ANALYSIS_BYTES: usize = 16 * 1024;
pub const MAX_PACKET_PAYLOAD_PREVIEW_BYTES: usize = 4 * 1024;
const MAX_REASSEMBLED_TCP_BYTES: usize = 512 * 1024;
pub const MAX_HTTP_START_LINE_BYTES: usize = 512;
const MAX_HTTP_HEADER_FIELDS: usize = 16;
const MAX_HTTP_HEADER_NAME_BYTES: usize = 64;
pub const MAX_HTTP_HEADER_VALUE_BYTES: usize = 256;
const MAX_PROXY_FLOW_STATES: usize = 2_048;
const MAX_PROXY_SESSION_LABELS: usize = 4_096;
const MAX_PROXY_PENDING_SEGMENTS: usize = 64;
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
// RFC 6994 reserves TCP option kind 253 for experiments. The four-byte ExID
// keeps this app-local metadata distinguishable from other experiments. These
// synthetic packets exist only in the PCAP and are never transmitted.
const PROXY_CAPTURE_TCP_OPTION_KIND: u8 = 253;
const PROXY_CAPTURE_TCP_OPTION_EXPERIMENT_ID: [u8; 4] = *b"PAAS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyIngressProtocol {
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
pub enum ProxyPacketDirection {
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
pub struct ProxyPacketMarker {
    pub protocol: ProxyIngressProtocol,
    pub direction: ProxyPacketDirection,
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

#[doc(hidden)]
pub fn active_writer_health() -> Option<Arc<WriterHealth>> {
    runtime()
        .active
        .load_full()
        .map(|writer| writer.health.clone())
}

pub fn is_enabled() -> bool {
    runtime()
        .active
        .load_full()
        .is_some_and(|writer| writer.is_healthy())
}

pub fn set_enabled(path: PathBuf, enabled: bool) -> io::Result<()> {
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

#[doc(hidden)]
pub fn record(packet: &[u8]) {
    if let Some(writer) = runtime().active.load_full() {
        let _ = writer.record(packet);
    }
}

pub fn capture_tcp_stream(stream: TcpStream, protocol: ProxyIngressProtocol) -> CapturedTcpStream {
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

mod application;
mod direction;
mod formatting;
mod packet_parser;
mod proxy_tracker;
mod reassembly;
mod report;
mod stream;
mod writer;

pub use application::{analyze_application, analyze_http};
pub use direction::ProxyFlowObservation;
pub use direction::WindowDirectionTracker;
use direction::*;
pub use formatting::short_protocol;
use formatting::*;
pub use packet_parser::parse_ip_packet;
use proxy_tracker::*;
pub use proxy_tracker::{ProxyFlowTracker, flow_key};
use reassembly::*;
pub use reassembly::{tcp_has_flag, tcp_payload_sequence, tcp_sequence_span};
use report::*;
pub use report::{CaptureReport, CapturedPacket, ProtocolField, ProtocolLayer, read_report};
pub use stream::*;
pub use writer::{PacketWriter, WriterHealth, global_header, scan_compatible_capture};
