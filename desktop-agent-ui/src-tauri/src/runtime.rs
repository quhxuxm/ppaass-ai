use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::auth::AgentAccessToken;
use crate::logging::UiLogBuffer;
#[cfg(windows)]
use crate::models::VerifiedProxyAuthStatus;
use crate::models::{AgentAuthAccount, AgentAuthAccountStatus, AgentConfigSummary};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentPermissionTrust {
    CachedUnverified,
    ServerVerified,
}

#[derive(Clone)]
pub(crate) struct AuthenticatedAgentSession {
    pub(crate) account: AgentAuthAccount,
    pub(crate) account_status: AgentAuthAccountStatus,
    pub(crate) permission_trust: AgentPermissionTrust,
    pub(crate) private_key_path: PathBuf,
    pub(crate) proxy_identity_public_key_path: PathBuf,
    pub(crate) proxy_web_url: String,
    pub(crate) agent_access_token: Option<AgentAccessToken>,
}

impl AuthenticatedAgentSession {
    pub(crate) fn new(
        account: AgentAuthAccount,
        account_status: AgentAuthAccountStatus,
        private_key_path: PathBuf,
        proxy_identity_public_key_path: PathBuf,
        proxy_web_url: String,
        agent_access_token: Option<AgentAccessToken>,
        permission_trust: AgentPermissionTrust,
    ) -> Self {
        let account = match permission_trust {
            AgentPermissionTrust::CachedUnverified => account.unverified_cache_projection(),
            AgentPermissionTrust::ServerVerified => account,
        };
        Self {
            account,
            account_status,
            permission_trust,
            private_key_path,
            proxy_identity_public_key_path,
            proxy_web_url,
            agent_access_token,
        }
    }
}

#[derive(Clone)]
pub(crate) struct PendingAgentDeviceAuthorization {
    pub(crate) id: u64,
    pub(crate) device_code: Zeroizing<String>,
    pub(crate) proxy_web_url: String,
    pub(crate) config_path: PathBuf,
    pub(crate) user_code: String,
    pub(crate) expires_at: i64,
    pub(crate) interval_seconds: u32,
}

pub(crate) struct AgentRuntime {
    pub(crate) agent: Mutex<Option<EmbeddedAgent>>,
    pub(crate) auth_operation: tokio::sync::Mutex<()>,
    authenticated_session: Mutex<Option<AuthenticatedAgentSession>>,
    permission_sync_error: Mutex<Option<String>>,
    pub(crate) permission_sync_in_progress: AtomicBool,
    pub(crate) permission_sync_notify: tokio::sync::Notify,
    pending_device_authorization: Mutex<Option<PendingAgentDeviceAuthorization>>,
    next_device_authorization_id: AtomicU64,
    #[cfg(windows)]
    verified_proxy_auth_status: Mutex<Option<VerifiedProxyAuthStatus>>,
    pub(crate) config_path: Mutex<Option<PathBuf>>,
    pub(crate) ui_config_path: Mutex<Option<PathBuf>>,
    pub(crate) trusted_config_baseline: Mutex<Option<AgentConfigSummary>>,
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
            permission_sync_error: Mutex::new(None),
            permission_sync_in_progress: AtomicBool::new(false),
            permission_sync_notify: tokio::sync::Notify::new(),
            pending_device_authorization: Mutex::new(None),
            next_device_authorization_id: AtomicU64::new(1),
            #[cfg(windows)]
            verified_proxy_auth_status: Mutex::new(None),
            config_path: Mutex::new(None),
            ui_config_path: Mutex::new(None),
            trusted_config_baseline: Mutex::new(None),
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
        session: AuthenticatedAgentSession,
    ) -> Result<(), String> {
        *self
            .authenticated_session
            .lock()
            .map_err(|_| "登录状态锁已损坏".to_string())? = Some(session);
        *self
            .permission_sync_error
            .lock()
            .map_err(|_| "权限同步状态锁已损坏".to_string())? = None;
        self.permission_sync_notify.notify_one();
        Ok(())
    }

    pub(crate) fn permission_sync_error(&self) -> Result<Option<String>, String> {
        self.permission_sync_error
            .lock()
            .map_err(|_| "权限同步状态锁已损坏".to_string())
            .map(|error| error.clone())
    }

    pub(crate) fn set_permission_sync_error(&self, error: Option<String>) -> Result<(), String> {
        *self
            .permission_sync_error
            .lock()
            .map_err(|_| "权限同步状态锁已损坏".to_string())? = error;
        Ok(())
    }

    pub(crate) fn update_authenticated_session_from_sync(
        &self,
        expected_username: &str,
        expected_token: &str,
        account: AgentAuthAccount,
        account_status: AgentAuthAccountStatus,
        agent_access_token: AgentAccessToken,
    ) -> Result<Option<AuthenticatedAgentSession>, String> {
        let mut authenticated = self
            .authenticated_session
            .lock()
            .map_err(|_| "登录状态锁已损坏".to_string())?;
        let Some(session) = authenticated.as_mut() else {
            return Ok(None);
        };
        if session.account.username != expected_username
            || session
                .agent_access_token
                .as_ref()
                .map(|token| token.value.as_str())
                != Some(expected_token)
        {
            return Ok(None);
        }
        session.account = account;
        session.account_status = account_status;
        session.agent_access_token = Some(agent_access_token);
        session.permission_trust = AgentPermissionTrust::ServerVerified;
        Ok(Some(session.clone()))
    }

    pub(crate) fn take_authenticated_session(
        &self,
    ) -> Result<Option<AuthenticatedAgentSession>, String> {
        let result = self
            .authenticated_session
            .lock()
            .map_err(|_| "登录状态锁已损坏".to_string())
            .map(|mut session| session.take());
        if matches!(&result, Ok(Some(_))) {
            let _ = self.set_permission_sync_error(None);
        }
        result
    }

    pub(crate) fn set_pending_device_authorization(
        &self,
        device_code: Zeroizing<String>,
        proxy_web_url: String,
        config_path: PathBuf,
        user_code: String,
        expires_at: i64,
        interval_seconds: u32,
    ) -> Result<PendingAgentDeviceAuthorization, String> {
        let id = self
            .next_device_authorization_id
            .fetch_add(1, Ordering::Relaxed);
        let challenge = PendingAgentDeviceAuthorization {
            id,
            device_code,
            proxy_web_url,
            config_path,
            user_code,
            expires_at,
            interval_seconds,
        };
        *self
            .pending_device_authorization
            .lock()
            .map_err(|_| "设备登录状态锁已损坏".to_string())? = Some(challenge.clone());
        Ok(challenge)
    }

    pub(crate) fn pending_device_authorization(
        &self,
    ) -> Result<Option<PendingAgentDeviceAuthorization>, String> {
        self.pending_device_authorization
            .lock()
            .map_err(|_| "设备登录状态锁已损坏".to_string())
            .map(|challenge| challenge.clone())
    }

    pub(crate) fn cancel_pending_device_authorization(&self) -> Result<(), String> {
        self.pending_device_authorization
            .lock()
            .map_err(|_| "设备登录状态锁已损坏".to_string())?
            .take();
        Ok(())
    }

    pub(crate) fn take_pending_device_authorization_if(
        &self,
        expected_id: u64,
    ) -> Result<bool, String> {
        let mut challenge = self
            .pending_device_authorization
            .lock()
            .map_err(|_| "设备登录状态锁已损坏".to_string())?;
        if challenge
            .as_ref()
            .is_some_and(|challenge| challenge.id == expected_id)
        {
            challenge.take();
            return Ok(true);
        }
        Ok(false)
    }

    #[cfg(windows)]
    pub(crate) fn set_verified_proxy_auth_status(
        &self,
        status: VerifiedProxyAuthStatus,
    ) -> Result<(), String> {
        let mut current = self
            .verified_proxy_auth_status
            .lock()
            .map_err(|_| "Proxy 账号状态锁已损坏".to_string())?;
        if current.as_ref() != Some(&status) {
            *current = Some(status);
        }
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn verified_proxy_auth_status(
        &self,
    ) -> Result<Option<VerifiedProxyAuthStatus>, String> {
        self.verified_proxy_auth_status
            .lock()
            .map_err(|_| "Proxy 账号状态锁已损坏".to_string())
            .map(|status| status.clone())
    }

    pub(crate) fn set_authenticated_account_status(
        &self,
        username: &str,
        status: AgentAuthAccountStatus,
    ) -> Result<Option<AuthenticatedAgentSession>, String> {
        let mut session = self
            .authenticated_session
            .lock()
            .map_err(|_| "登录状态锁已损坏".to_string())?;
        let Some(current) = session.as_mut() else {
            return Ok(None);
        };
        if current.account.username != username || current.account_status == status {
            return Ok(None);
        }
        current.account_status = status;
        Ok(Some(current.clone()))
    }
}

#[cfg(test)]
mod tests;
