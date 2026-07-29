use super::*;

pub(super) struct CaptureRecord {
    pub(super) seconds: u32,
    pub(super) micros: u32,
    pub(super) original_len: u32,
    pub(super) packet: Vec<u8>,
}

pub(super) struct PacketWriter {
    pub(super) sender: Option<SyncSender<CaptureRecord>>,
    pub(super) writer: Option<JoinHandle<()>>,
    pub(super) dropped_packets: AtomicU64,
    pub(super) health: Arc<WriterHealth>,
}

#[derive(Default)]
pub(super) struct WriterHealth {
    pub(super) failed: AtomicBool,
}

impl WriterHealth {
    pub(super) fn is_healthy(&self) -> bool {
        !self.failed.load(Ordering::Acquire)
    }

    pub(super) fn mark_failed(&self, error: impl fmt::Display) {
        if !self.failed.swap(true, Ordering::AcqRel) {
            warn!("Android PCAP writer stopped after an I/O failure: {error}");
        }
    }
}

impl PacketWriter {
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

    pub(super) fn record(&self, packet: &[u8]) -> io::Result<()> {
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

    pub(super) fn is_healthy(&self) -> bool {
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

pub(super) fn writer_loop(file: File, receiver: Receiver<CaptureRecord>) -> io::Result<()> {
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

pub(super) fn write_record(writer: &mut impl Write, record: CaptureRecord) -> io::Result<()> {
    writer.write_all(&record.seconds.to_le_bytes())?;
    writer.write_all(&record.micros.to_le_bytes())?;
    writer.write_all(&(record.packet.len() as u32).to_le_bytes())?;
    writer.write_all(&record.original_len.to_le_bytes())?;
    writer.write_all(&record.packet)
}

pub(super) fn ensure_capture_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

pub(super) fn open_compatible_capture_for_append(path: &Path) -> io::Result<Option<File>> {
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

pub(super) fn scan_compatible_capture(reader: &mut impl BufRead, file_len: u64) -> io::Result<u64> {
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

pub(super) fn skip_buffered_exact(
    reader: &mut impl BufRead,
    mut remaining: usize,
) -> io::Result<bool> {
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

pub(super) fn global_header() -> [u8; 24] {
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

pub(super) fn write_global_header(file: &mut File) -> io::Result<()> {
    file.write_all(&global_header())
}
