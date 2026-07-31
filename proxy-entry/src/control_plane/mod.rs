mod authorization;
mod client;
mod events;
mod registration;

pub use client::{
    RemoteControlPlane, load_control_token, validate_advertised_address, validate_entry_id,
    validate_registry_url,
};

use async_trait::async_trait;
use proxy_control_protocol::AccessEvent;
use std::sync::Arc;

use crate::error::Result;

#[async_trait]
pub trait AccessEventSink: Send + Sync {
    async fn submit_access_batch(&self, batch_id: &str, events: &[AccessEvent]) -> Result<()>;
}

impl RemoteControlPlane {
    pub(crate) fn start_background_tasks(self: &Arc<Self>) {
        events::spawn_authorization_event_listener(Arc::downgrade(self));
        registration::spawn_entry_registration(Arc::downgrade(self));
    }
}
