use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use tokio::sync::broadcast;

const EVENT_BUFFER_CAPACITY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentServerEvent {
    pub(crate) revision: u64,
    pub(crate) kind: &'static str,
    account_id: Option<Arc<str>>,
}

impl AgentServerEvent {
    pub(crate) fn is_visible_to(&self, account_id: &str) -> bool {
        self.account_id
            .as_deref()
            .is_none_or(|target| target == account_id)
    }
}

#[derive(Clone)]
pub struct AgentEventHub {
    sender: broadcast::Sender<AgentServerEvent>,
    next_revision: Arc<AtomicU64>,
}

impl Default for AgentEventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentEventHub {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(EVENT_BUFFER_CAPACITY);
        Self {
            sender,
            next_revision: Arc::new(AtomicU64::new(1)),
        }
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<AgentServerEvent> {
        self.sender.subscribe()
    }

    pub(crate) fn publish_profile_changed(&self, account_id: &str) {
        self.publish("profile_changed", Some(account_id));
    }

    pub(crate) fn publish_key_request_changed(&self, account_id: &str) {
        self.publish("key_request_changed", Some(account_id));
    }

    pub(crate) fn publish_all_profiles_changed(&self) {
        self.publish("profiles_changed", None);
    }

    pub(crate) fn publish_admin_key_requests_changed(&self) {
        self.publish("admin_key_requests_changed", None);
    }

    fn publish(&self, kind: &'static str, account_id: Option<&str>) {
        let revision = self.next_revision.fetch_add(1, Ordering::Relaxed);
        let _ = self.sender.send(AgentServerEvent {
            revision,
            kind,
            account_id: account_id.map(Arc::from),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn targeted_and_global_events_keep_monotonic_revisions() {
        let hub = AgentEventHub::new();
        let mut receiver = hub.subscribe();
        hub.publish_profile_changed("acc_one");
        hub.publish_admin_key_requests_changed();

        let targeted = receiver.recv().await.unwrap();
        let global = receiver.recv().await.unwrap();
        assert!(targeted.is_visible_to("acc_one"));
        assert!(!targeted.is_visible_to("acc_two"));
        assert!(global.is_visible_to("acc_two"));
        assert!(global.revision > targeted.revision);
    }
}
