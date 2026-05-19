use std::sync::atomic::AtomicU64;

pub struct UserBandwidth {
    /// proxy 发往 agent 的字节数。
    pub bytes_sent: AtomicU64,
    /// proxy 从 agent 收到的字节数。
    pub bytes_received: AtomicU64,
    /// 以 UNIX_EPOCH 以来的毫秒数存储，用于无锁访问
    pub last_reset_millis: AtomicU64,
    /// None 表示不限速。
    pub limit_mbps: Option<u64>,
}
