use std::future::Future;
use std::sync::Arc;

use tokio::sync::{Mutex, oneshot, watch};

enum SlotState<H> {
    Empty,
    Initializing,
    Ready(H),
}

struct UdpSessionSlotInner<H> {
    state: Mutex<SlotState<H>>,
    changes: watch::Sender<u64>,
}

/// Coordinates one UDP-session pool slot without holding its mutex while an
/// authentication round trip is in flight.
#[derive(Clone)]
pub struct UdpSessionSlot<H> {
    inner: Arc<UdpSessionSlotInner<H>>,
}

impl<H> UdpSessionSlot<H>
where
    H: Clone + Send + 'static,
{
    pub fn new() -> Self {
        let (changes, _) = watch::channel(0_u64);
        Self {
            inner: Arc::new(UdpSessionSlotInner {
                state: Mutex::new(SlotState::Empty),
                changes,
            }),
        }
    }

    /// Returns the ready handle or starts exactly one detached initializer.
    /// The task owns the state transition, so canceling an individual waiter
    /// cannot leave a slot permanently stuck in `Initializing`.
    pub async fn get_or_initialize<P, F, Fut, E>(
        &self,
        usable: P,
        initialize: F,
    ) -> std::result::Result<H, E>
    where
        P: Fn(&H) -> bool,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = std::result::Result<H, E>> + Send + 'static,
        E: From<std::io::Error> + Send + 'static,
    {
        let mut initialize = Some(initialize);
        loop {
            let mut changes = self.inner.changes.subscribe();
            let initialize_now = {
                let mut state = self.inner.state.lock().await;
                match &*state {
                    SlotState::Ready(handle) if usable(handle) => return Ok(handle.clone()),
                    SlotState::Initializing => false,
                    SlotState::Empty | SlotState::Ready(_) => {
                        *state = SlotState::Initializing;
                        true
                    }
                }
            };

            if initialize_now {
                let initializer = initialize
                    .take()
                    .expect("UDP slot initializer is used at most once per caller");
                let (result_tx, result_rx) = oneshot::channel();
                let slot = self.clone();
                tokio::spawn(async move {
                    let result = initializer().await;
                    {
                        let mut state = slot.inner.state.lock().await;
                        *state = match &result {
                            Ok(handle) => SlotState::Ready(handle.clone()),
                            Err(_) => SlotState::Empty,
                        };
                    }
                    slot.publish_change();
                    let _ = result_tx.send(result);
                });
                return result_rx.await.map_err(|_| {
                    E::from(std::io::Error::other(
                        "UDP session initializer terminated unexpectedly",
                    ))
                })?;
            }

            // `watch` retains the most recent revision, so an initialization
            // that finishes between the state read and `changed()` is not lost.
            let _ = changes.changed().await;
        }
    }

    pub async fn invalidate_if<P>(&self, predicate: P) -> bool
    where
        P: FnOnce(&H) -> bool,
    {
        let invalidated = {
            let mut state = self.inner.state.lock().await;
            match &*state {
                SlotState::Ready(handle) if predicate(handle) => {
                    *state = SlotState::Empty;
                    true
                }
                _ => false,
            }
        };
        if invalidated {
            self.publish_change();
        }
        invalidated
    }

    fn publish_change(&self) {
        let revision = (*self.inner.changes.borrow()).wrapping_add(1);
        self.inner.changes.send_replace(revision);
    }
}

impl<H> Default for UdpSessionSlot<H>
where
    H: Clone + Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}
