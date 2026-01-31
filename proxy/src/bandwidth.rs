use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct BandwidthMonitor {
    user_bandwidth: Arc<DashMap<String, UserBandwidth>>,
}

struct UserBandwidth {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    last_reset: RwLock<Instant>,
    limit_mbps: Option<u64>,
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
            last_reset: RwLock::new(Instant::now()),
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
            && let Some(limit_mbps) = entry.limit_mbps {
                let last_reset = entry.last_reset.read().await;
                let elapsed = last_reset.elapsed();

                if elapsed >= Duration::from_secs(1) {
                    // Reset counters every second
                    drop(last_reset);
                    let mut last_reset = entry.last_reset.write().await;
                    *last_reset = Instant::now();
                    entry.bytes_sent.store(0, Ordering::Relaxed);
                    entry.bytes_received.store(0, Ordering::Relaxed);
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
