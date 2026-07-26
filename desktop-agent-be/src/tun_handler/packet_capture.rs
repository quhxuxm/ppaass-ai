//! TUN 双向明文包 PCAP 写入器。
//!
//! TUN 设备提供的是不含二层头的 IPv4/IPv6 包，因此使用 libpcap 的
//! DLT_RAW（101）。网络热路径只复制数据并尝试投递到有界队列，独立线程负责
//! 批量落盘；磁盘变慢时丢弃抓包副本，绝不反压代理流量。

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{error, warn};

const PCAP_SNAPLEN: u32 = 65_535;
const PCAP_LINKTYPE_RAW: u32 = 101;
const CAPTURE_QUEUE_PACKETS: usize = 4_096;
const WRITER_BUFFER_BYTES: usize = 256 * 1024;
const WRITER_BATCH_PACKETS: usize = 512;
const WRITER_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone)]
pub struct PacketCaptureController {
    path: Arc<PathBuf>,
    active: Arc<ArcSwapOption<PacketCapture>>,
    transition: Arc<Mutex<()>>,
}

impl PacketCaptureController {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
            active: Arc::new(ArcSwapOption::empty()),
            transition: Arc::new(Mutex::new(())),
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
                .store(Some(Arc::new(PacketCapture::create(&self.path)?)));
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
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
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

fn write_global_header(file: &mut File) -> io::Result<()> {
    let mut header = Vec::with_capacity(24);
    header.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
    header.extend_from_slice(&2_u16.to_le_bytes());
    header.extend_from_slice(&4_u16.to_le_bytes());
    header.extend_from_slice(&0_i32.to_le_bytes());
    header.extend_from_slice(&0_u32.to_le_bytes());
    header.extend_from_slice(&PCAP_SNAPLEN.to_le_bytes());
    header.extend_from_slice(&PCAP_LINKTYPE_RAW.to_le_bytes());
    file.write_all(&header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn asynchronously_writes_raw_ip_pcap_header_and_packet() {
        let path = std::env::temp_dir().join(format!(
            "ppaass-packet-capture-{}-{}.pcap",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
        let path = std::env::temp_dir().join(format!(
            "ppaass-packet-capture-controller-{}-{}.pcap",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
}
