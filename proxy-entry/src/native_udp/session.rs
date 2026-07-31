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

pub const FLOW_CREATION_BURST: f64 = 64.0;
const FLOW_CREATION_REFILL_PER_SECOND: f64 = 16.0;
const FLOW_AUTHORIZATION_COALESCE_WINDOW: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct SessionContext {
    pub socket: Arc<UdpSocket>,
    pub config: Arc<ProxyConfig>,
    pub user_manager: Arc<UserManager>,
    pub egress_state: Arc<EgressState>,
    pub access_recorder: AccessRecorder,
    pub username: String,
    pub authenticated_public_key_pem: String,
    pub authenticated_key_version: Option<i64>,
    pub expires_at: Option<i64>,
    pub peer: SocketAddr,
}

struct ChannelState {
    input_tx: Option<mpsc::Sender<Vec<u8>>>,
    abort_handle: AbortHandle,
}

pub mod admission;
pub mod lifecycle;
mod runner;

use admission::*;
pub use lifecycle::*;
pub(super) use runner::ChannelEvent;
pub use runner::run_session;
