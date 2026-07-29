use super::*;

pub(super) struct CaptureRecord {
    seconds: u32,
    micros: u32,
    original_len: u32,
    packet: Vec<u8>,
}

pub(super) struct PacketCapture {
    pub(super) sender: Option<SyncSender<CaptureRecord>>,
    pub(super) writer: Option<JoinHandle<()>>,
    pub(super) dropped_packets: AtomicU64,
    pub(super) disabled: AtomicBool,
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

    pub(super) fn start_writer(file: File) -> io::Result<Self> {
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

pub(super) fn global_header() -> [u8; 24] {
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
