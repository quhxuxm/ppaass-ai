use crate::store::{
    AgentWebSessionHandoffConsume, AgentWebSessionHandoffCreate, AgentWebSessionHandoffRepository,
    NewAgentWebSessionHandoff, WebAccount,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::error;

use crate::auth::random_token;

pub const AGENT_WEB_SESSION_HANDOFF_TTL_SECONDS: i64 = 90;
const AGENT_WEB_SESSION_HANDOFF_CODE_BYTES: usize = 32;
const MAX_ACTIVE_HANDOFFS: u32 = 4_096;
const MAX_ACTIVE_HANDOFFS_PER_ACCOUNT: u32 = 4;
const HANDOFF_HASH_DOMAIN: &[u8] = b"ppaass-agent-web-session-handoff-v1\0";

#[derive(Clone)]
pub struct AgentWebSessionHandoffStore {
    repository: Arc<dyn AgentWebSessionHandoffRepository>,
    maximum_entries: u32,
    maximum_entries_per_account: u32,
}

pub struct IssuedAgentWebSessionHandoff {
    pub code: String,
    pub expires_at: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AgentWebSessionHandoffClaim {
    pub account_id: String,
    pub account_auth_version: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentWebSessionHandoffIssueError {
    Capacity,
    Storage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentWebSessionHandoffConsumeError {
    InvalidOrConsumed,
    Expired,
    Storage,
}

impl AgentWebSessionHandoffStore {
    pub fn new(repository: Arc<dyn AgentWebSessionHandoffRepository>) -> Self {
        Self::with_limits(
            repository,
            MAX_ACTIVE_HANDOFFS,
            MAX_ACTIVE_HANDOFFS_PER_ACCOUNT,
        )
    }

    #[doc(hidden)]
    pub fn with_limits(
        repository: Arc<dyn AgentWebSessionHandoffRepository>,
        maximum_entries: u32,
        maximum_entries_per_account: u32,
    ) -> Self {
        Self {
            repository,
            maximum_entries: maximum_entries.max(1),
            maximum_entries_per_account: maximum_entries_per_account.max(1),
        }
    }

    pub async fn issue(
        &self,
        account: &WebAccount,
    ) -> Result<IssuedAgentWebSessionHandoff, AgentWebSessionHandoffIssueError> {
        self.issue_at(&account.account_id, account.auth_version, now())
            .await
    }

    pub async fn consume(
        &self,
        code: &str,
    ) -> Result<AgentWebSessionHandoffClaim, AgentWebSessionHandoffConsumeError> {
        self.consume_at(code, now()).await
    }

    #[doc(hidden)]
    pub async fn issue_at(
        &self,
        account_id: &str,
        account_auth_version: i64,
        issued_at: i64,
    ) -> Result<IssuedAgentWebSessionHandoff, AgentWebSessionHandoffIssueError> {
        let expires_at = issued_at.saturating_add(AGENT_WEB_SESSION_HANDOFF_TTL_SECONDS);
        for _ in 0..3 {
            let code = random_token(AGENT_WEB_SESSION_HANDOFF_CODE_BYTES);
            let Some(code_hash) = handoff_code_hash(&code) else {
                continue;
            };
            let result = self
                .repository
                .create_agent_web_session_handoff(
                    NewAgentWebSessionHandoff {
                        code_hash,
                        account_id: account_id.to_string(),
                        account_auth_version,
                        expires_at,
                    },
                    issued_at,
                    self.maximum_entries,
                    self.maximum_entries_per_account,
                )
                .await;
            match result {
                Ok(AgentWebSessionHandoffCreate::Created) => {
                    return Ok(IssuedAgentWebSessionHandoff { code, expires_at });
                }
                Ok(AgentWebSessionHandoffCreate::Capacity) => {
                    return Err(AgentWebSessionHandoffIssueError::Capacity);
                }
                Ok(AgentWebSessionHandoffCreate::Conflict) => {}
                Err(error) => {
                    error!(%error, "写入 Agent Web 会话交接失败");
                    return Err(AgentWebSessionHandoffIssueError::Storage);
                }
            }
        }
        Err(AgentWebSessionHandoffIssueError::Capacity)
    }

    #[doc(hidden)]
    pub async fn consume_at(
        &self,
        code: &str,
        consumed_at: i64,
    ) -> Result<AgentWebSessionHandoffClaim, AgentWebSessionHandoffConsumeError> {
        let code_hash =
            handoff_code_hash(code).ok_or(AgentWebSessionHandoffConsumeError::InvalidOrConsumed)?;
        match self
            .repository
            .consume_agent_web_session_handoff(&code_hash, consumed_at)
            .await
        {
            Ok(AgentWebSessionHandoffConsume::Claimed {
                account_id,
                account_auth_version,
            }) => Ok(AgentWebSessionHandoffClaim {
                account_id,
                account_auth_version,
            }),
            Ok(AgentWebSessionHandoffConsume::Expired) => {
                Err(AgentWebSessionHandoffConsumeError::Expired)
            }
            Ok(AgentWebSessionHandoffConsume::NotFound) => {
                Err(AgentWebSessionHandoffConsumeError::InvalidOrConsumed)
            }
            Err(error) => {
                error!(%error, "读取 Agent Web 会话交接失败");
                Err(AgentWebSessionHandoffConsumeError::Storage)
            }
        }
    }
}

fn handoff_code_hash(code: &str) -> Option<String> {
    if code.len() != 43 || !code.is_ascii() || code.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(code).ok()?;
    if decoded.len() != AGENT_WEB_SESSION_HANDOFF_CODE_BYTES {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(HANDOFF_HASH_DOMAIN);
    digest.update(decoded);
    Some(URL_SAFE_NO_PAD.encode(digest.finalize()))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
