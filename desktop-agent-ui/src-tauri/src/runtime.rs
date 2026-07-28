use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use tokio_util::sync::CancellationToken;

use crate::logging::UiLogBuffer;
use crate::models::AgentAuthAccount;

#[derive(Clone)]
pub(crate) struct AuthenticatedAgentSession {
    pub(crate) account: AgentAuthAccount,
    pub(crate) private_key_path: PathBuf,
    pub(crate) proxy_web_url: String,
}

pub(crate) struct AgentRuntime {
    pub(crate) agent: Mutex<Option<EmbeddedAgent>>,
    pub(crate) auth_operation: tokio::sync::Mutex<()>,
    authenticated_session: Mutex<Option<AuthenticatedAgentSession>>,
    pub(crate) config_path: Mutex<Option<PathBuf>>,
    pub(crate) ui_config_path: Mutex<Option<PathBuf>>,
    pub(crate) packet_capture_enabled: AtomicBool,
    pub(crate) logs: UiLogBuffer,
    pub(crate) last_error: Arc<Mutex<Option<String>>>,
}

pub(crate) struct EmbeddedAgent {
    pub(crate) shutdown: CancellationToken,
    pub(crate) join: Option<JoinHandle<()>>,
    pub(crate) packet_capture: desktop_agent_be::PacketCaptureController,
}

impl AgentRuntime {
    pub(crate) fn new() -> Self {
        Self {
            agent: Mutex::new(None),
            auth_operation: tokio::sync::Mutex::new(()),
            authenticated_session: Mutex::new(None),
            config_path: Mutex::new(None),
            ui_config_path: Mutex::new(None),
            packet_capture_enabled: AtomicBool::new(false),
            logs: UiLogBuffer::new(1200),
            last_error: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn is_authenticated(&self) -> bool {
        self.authenticated_session
            .lock()
            .map(|session| session.is_some())
            .unwrap_or(false)
    }

    pub(crate) fn require_authenticated(&self) -> Result<(), String> {
        self.is_authenticated()
            .then_some(())
            .ok_or_else(|| "请先登录 Proxy Web 账号".to_string())
    }

    pub(crate) fn authenticated_session(
        &self,
    ) -> Result<Option<AuthenticatedAgentSession>, String> {
        self.authenticated_session
            .lock()
            .map_err(|_| "登录状态锁已损坏".to_string())
            .map(|session| session.clone())
    }

    pub(crate) fn require_authenticated_session(
        &self,
    ) -> Result<AuthenticatedAgentSession, String> {
        self.authenticated_session()?
            .ok_or_else(|| "请先登录 Proxy Web 账号".to_string())
    }

    pub(crate) fn set_authenticated_session(
        &self,
        account: AgentAuthAccount,
        private_key_path: PathBuf,
        proxy_web_url: String,
    ) -> Result<(), String> {
        *self
            .authenticated_session
            .lock()
            .map_err(|_| "登录状态锁已损坏".to_string())? = Some(AuthenticatedAgentSession {
            account,
            private_key_path,
            proxy_web_url,
        });
        Ok(())
    }

    pub(crate) fn take_authenticated_session(
        &self,
    ) -> Result<Option<AuthenticatedAgentSession>, String> {
        self.authenticated_session
            .lock()
            .map_err(|_| "登录状态锁已损坏".to_string())
            .map(|mut session| session.take())
    }
}
