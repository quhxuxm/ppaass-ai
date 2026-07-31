mod authorization;
mod client;
mod events;

pub use client::{RemoteControlPlane, load_control_token, validate_control_url, validate_entry_id};

use async_trait::async_trait;
use proxy_control_protocol::AccessEvent;

use crate::error::Result;

#[async_trait]
pub trait AccessEventSink: Send + Sync {
    async fn submit_access_batch(&self, batch_id: &str, events: &[AccessEvent]) -> Result<()>;
}
