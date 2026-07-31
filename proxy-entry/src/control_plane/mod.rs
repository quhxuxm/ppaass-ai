mod authorization;
mod client;
mod events;

pub(crate) use client::RemoteControlPlane;

use async_trait::async_trait;
use proxy_control_protocol::AccessEvent;

use crate::error::Result;

#[async_trait]
pub(crate) trait AccessEventSink: Send + Sync {
    async fn submit_access_batch(&self, batch_id: &str, events: &[AccessEvent]) -> Result<()>;
}
