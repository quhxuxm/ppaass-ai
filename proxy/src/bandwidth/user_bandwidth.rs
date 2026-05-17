use std::sync::atomic::AtomicU64;

pub struct UserBandwidth {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    /// 以 UNIX_EPOCH 以来的毫秒数存储，用于无锁访问
    pub last_reset_millis: AtomicU64,
    pub limit_mbps: Option<u64>,
}
