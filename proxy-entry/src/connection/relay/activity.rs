use std::sync::atomic::{AtomicU64, Ordering};

use futures::task::AtomicWaker;

/// Lock-free activity signal shared by both directions of a TCP relay.
///
/// `watch::Sender::send` used to run for every successful read or write. The
/// relay only needs an edge notification to reset its idle timer, so an atomic
/// epoch plus waker avoids putting a channel synchronization primitive on the
/// byte-copy path.
#[derive(Default)]
pub struct RelayActivity {
    epoch: AtomicU64,
    waker: AtomicWaker,
}

impl RelayActivity {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observed_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub fn mark(&self) {
        self.epoch.fetch_add(1, Ordering::Release);
        self.waker.wake();
    }

    pub async fn changed_since(&self, observed: &mut u64) {
        futures::future::poll_fn(|cx| {
            self.waker.register(cx.waker());
            let current = self.epoch.load(Ordering::Acquire);
            if current != *observed {
                *observed = current;
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
    }
}
