use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Bandwidth limiter using token bucket algorithm
#[derive(Clone)]
pub struct BandwidthLimiter {
    inner: Arc<Mutex<BandwidthLimiterInner>>,
}

struct BandwidthLimiterInner {
    bytes_per_second: u64,
    tokens: f64,
    last_update: Instant,
}

impl BandwidthLimiter {
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BandwidthLimiterInner {
                bytes_per_second,
                tokens: bytes_per_second as f64,
                last_update: Instant::now(),
            })),
        }
    }

    /// Try to consume tokens, returns true if allowed
    pub fn try_consume(&self, bytes: u64) -> bool {
        let mut inner = self.inner.lock();
        inner.refill_tokens();

        if inner.tokens >= bytes as f64 {
            inner.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }

    /// Wait until tokens are available (async)
    pub async fn consume(&self, bytes: u64) {
        loop {
            if self.try_consume(bytes) {
                return;
            }
            // Wait a bit before retrying
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Update bandwidth limit
    pub fn set_limit(&self, bytes_per_second: u64) {
        let mut inner = self.inner.lock();
        inner.bytes_per_second = bytes_per_second;
    }
}

impl BandwidthLimiterInner {
    fn refill_tokens(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update);
        let new_tokens = elapsed.as_secs_f64() * self.bytes_per_second as f64;

        self.tokens = (self.tokens + new_tokens).min(self.bytes_per_second as f64);
        self.last_update = now;
    }
}

/// Bandwidth usage tracker
#[derive(Clone)]
pub struct BandwidthTracker {
    inner: Arc<Mutex<BandwidthTrackerInner>>,
}

struct BandwidthTrackerInner {
    total_bytes: u64,
    bytes_in_window: u64,
    window_start: Instant,
    window_duration: Duration,
}

impl BandwidthTracker {
    pub fn new(window_duration: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BandwidthTrackerInner {
                total_bytes: 0,
                bytes_in_window: 0,
                window_start: Instant::now(),
                window_duration,
            })),
        }
    }

    /// Record bytes transferred
    pub fn record(&self, bytes: u64) {
        let mut inner = self.inner.lock();
        inner.reset_window_if_needed();
        inner.total_bytes += bytes;
        inner.bytes_in_window += bytes;
    }

    /// Get total bytes transferred
    pub fn total_bytes(&self) -> u64 {
        self.inner.lock().total_bytes
    }

    /// Get current bandwidth usage (bytes per second)
    pub fn current_bandwidth(&self) -> u64 {
        let mut inner = self.inner.lock();
        inner.reset_window_if_needed();
        let elapsed = inner.window_start.elapsed();
        if elapsed.as_secs() > 0 {
            inner.bytes_in_window / elapsed.as_secs()
        } else {
            0
        }
    }
}

impl BandwidthTrackerInner {
    fn reset_window_if_needed(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= self.window_duration {
            self.bytes_in_window = 0;
            self.window_start = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bandwidth_limiter() {
        let limiter = BandwidthLimiter::new(1000);
        assert!(limiter.try_consume(500));
        assert!(limiter.try_consume(500));
        assert!(!limiter.try_consume(100)); // Should fail, no tokens left
    }

    #[test]
    fn test_bandwidth_tracker() {
        let tracker = BandwidthTracker::new(Duration::from_secs(1));
        tracker.record(1000);
        tracker.record(500);
        assert_eq!(tracker.total_bytes(), 1500);
    }
}
