use super::auth::validate_session_authorization;
use super::channel::run_channel_worker;
use super::session_label;
use crate::access_log::AccessRecorder;
use crate::config::ProxyConfig;
use crate::connection::EgressState;
use crate::error::{ProxyError, Result};
use crate::user_manager::UserManager;
use protocol::udp_transport::{UdpSessionCodec, UdpSessionMessage};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;
use tracing::{debug, trace, warn};

const FLOW_CREATION_BURST: f64 = 64.0;
const FLOW_CREATION_REFILL_PER_SECOND: f64 = 16.0;
const FLOW_AUTHORIZATION_COALESCE_WINDOW: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub(super) struct SessionContext {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) config: Arc<ProxyConfig>,
    pub(super) user_manager: Arc<UserManager>,
    pub(super) egress_state: Arc<EgressState>,
    pub(super) access_recorder: AccessRecorder,
    pub(super) username: String,
    pub(super) authenticated_public_key_pem: String,
    pub(super) authenticated_key_version: Option<i64>,
    pub(super) expires_at: Option<i64>,
    pub(super) peer: SocketAddr,
}

struct ChannelState {
    input_tx: Option<mpsc::Sender<Vec<u8>>>,
    abort_handle: AbortHandle,
}

mod admission;
mod lifecycle;
mod runner;

use admission::*;
pub(super) use lifecycle::*;
pub(super) use runner::{ChannelEvent, run_session};

#[cfg(test)]
mod tests;
