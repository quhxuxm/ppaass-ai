pub(super) struct TokenBucket {
    tokens: f64,
    updated_at: f64,
    pub(super) last_seen_at: f64,
}

impl TokenBucket {
    pub(super) fn full(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            updated_at: 0.0,
            last_seen_at: 0.0,
        }
    }

    pub(super) fn retry_after(
        &mut self,
        now: f64,
        capacity: f64,
        refill_per_second: f64,
    ) -> Option<u32> {
        let elapsed = (now - self.updated_at).max(0.0);
        self.tokens = (self.tokens + elapsed * refill_per_second).min(capacity);
        self.updated_at = now;
        self.last_seen_at = now;
        if self.tokens >= 1.0 {
            None
        } else {
            Some((((1.0 - self.tokens) / refill_per_second).ceil() as u32).max(1))
        }
    }

    pub(super) fn consume(&mut self) {
        self.tokens = (self.tokens - 1.0).max(0.0);
    }
}
