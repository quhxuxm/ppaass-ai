use std::sync::atomic::AtomicU64;

pub struct UserBandwidth {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    /// Stored as milliseconds since UNIX_EPOCH for lock-free access
    pub last_reset_millis: AtomicU64,
    pub limit_mbps: Option<u64>,
}
