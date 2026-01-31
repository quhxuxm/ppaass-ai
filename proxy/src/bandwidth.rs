use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct BandwidthMonitor {
    user_bandwidth: Arc<DashMap<String, UserBandwidth>>,
}

struct UserBandwidth {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    /// Stored as milliseconds since UNIX_EPOCH for lock-free access
    last_reset_millis: AtomicU64,
    limit_mbps: Option<u64>,
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
                // Reset counters every second using compare-and-swap
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

            // Convert limit from Mbps to bytes per second
            let limit_bytes_per_sec = (limit_mbps * 1_000_000) / 8;

            return total_bytes < limit_bytes_per_sec;
        }
        true
    }

    pub fn get_all_stats(&self) -> Vec<(String, u64, u64)> {
        self.user_bandwidth
            .iter()
            .map(|entry| {
                let username = entry.key().clone();
                let bytes_sent = entry.bytes_sent.load(Ordering::Relaxed);
                let bytes_received = entry.bytes_received.load(Ordering::Relaxed);
                (username, bytes_sent, bytes_received)
            })
            .collect()
    }
}

impl Default for BandwidthMonitor {
    fn default() -> Self {
        Self::new()
    }
}
