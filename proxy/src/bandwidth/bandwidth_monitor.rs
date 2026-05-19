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
        // DashMap 允许不同用户的带宽计数并发更新，不需要全局锁。
        Self {
            user_bandwidth: Arc::new(DashMap::new()),
        }
    }

    pub fn register_user(&self, username: String, limit_mbps: Option<u64>) {
        // 每个用户独立维护收发计数和重置时间，限速判断只影响该用户。
        let user_bandwidth = UserBandwidth {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            last_reset_millis: AtomicU64::new(current_time_millis()),
            limit_mbps,
        };
        self.user_bandwidth.insert(username, user_bandwidth);
    }

    pub fn record_sent(&self, username: &str, bytes: u64) {
        // 发送方向指 proxy 写回 agent 的字节数，用于下行限速统计。
        if let Some(entry) = self.user_bandwidth.get(username) {
            entry.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn record_received(&self, username: &str, bytes: u64) {
        // 接收方向指 proxy 从 agent 收到的字节数，用于上行限速统计。
        if let Some(entry) = self.user_bandwidth.get(username) {
            entry.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub async fn check_limit(&self, username: &str) -> bool {
        // 未配置用户或未配置 limit_mbps 时直接放行。
        if let Some(entry) = self.user_bandwidth.get(username)
            && let Some(limit_mbps) = entry.limit_mbps
        {
            let last_reset = entry.last_reset_millis.load(Ordering::Relaxed);
            let now = current_time_millis();
            let elapsed_ms = now.saturating_sub(last_reset);

            if elapsed_ms >= 1000 {
                // 使用 compare-and-swap 每秒重置计数器，避免多个连接同时清零。
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

            // 将 Mbps 限制转换为每秒字节数，收发方向合并做总量限制。
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
