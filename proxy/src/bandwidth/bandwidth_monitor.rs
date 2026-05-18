use super::user_bandwidth::UserBandwidth;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct BandwidthMonitor {
    user_bandwidth: Arc<DashMap<String, UserBandwidth>>,
}

fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

impl BandwidthMonitor {
    pub fn new() -> Self {
        Self {
            user_bandwidth: Arc::new(DashMap::new()),
        }
    }

    pub fn register_user(&self, username: String, limit_mbps: Option<u64>) {
        let user_bandwidth = UserBandwidth {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            last_reset_millis: AtomicU64::new(current_time_millis()),
            limit_mbps,
        };
        self.user_bandwidth.insert(username, user_bandwidth);
    }

    pub fn record_sent(&self, username: &str, bytes: u64) {
        if let Some(entry) = self.user_bandwidth.get(username) {
            entry.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn record_received(&self, username: &str, bytes: u64) {
        if let Some(entry) = self.user_bandwidth.get(username) {
            entry.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub async fn check_limit(&self, username: &str) -> bool {
        if let Some(entry) = self.user_bandwidth.get(username)
            && let Some(limit_mbps) = entry.limit_mbps
        {
            let last_reset = entry.last_reset_millis.load(Ordering::Relaxed);
            let now = current_time_millis();
            let elapsed_ms = now.saturating_sub(last_reset);

            if elapsed_ms >= 1000 {
                // 使用 compare-and-swap 每秒重置计数器
                if entry
                    .last_reset_millis
                    .compare_exchange(last_reset, now, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    entry.bytes_sent.store(0, Ordering::Relaxed);
                    entry.bytes_received.store(0, Ordering::Relaxed);
                }
                return true;
            }

            let bytes_sent = entry.bytes_sent.load(Ordering::Relaxed);
            let bytes_received = entry.bytes_received.load(Ordering::Relaxed);
            let total_bytes = bytes_sent + bytes_received;

            // 将 Mbps 限制转换为每秒字节数
            let limit_bytes_per_sec = (limit_mbps * 1_000_000) / 8;

            return total_bytes < limit_bytes_per_sec;
        }
        true
    }
}

impl Default for BandwidthMonitor {
    fn default() -> Self {
        Self::new()
    }
}
