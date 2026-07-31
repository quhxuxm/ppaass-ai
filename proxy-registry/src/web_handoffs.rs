use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use proxy_user_store::{
    AgentWebSessionHandoffConsume, AgentWebSessionHandoffCreate, AgentWebSessionHandoffRepository,
    NewAgentWebSessionHandoff, WebAccount,
};
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

    fn with_limits(
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

    async fn issue_at(
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

    async fn consume_at(
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

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_user_store::{
        AccountRepository, AgentWebSessionHandoffRepository, NewAdminAccount, SqliteUserRepository,
    };
    use tempfile::TempDir;

    async fn test_store(
        maximum_entries: u32,
        maximum_entries_per_account: u32,
    ) -> (TempDir, AgentWebSessionHandoffStore) {
        let directory = TempDir::new().unwrap();
        let repository = Arc::new(
            SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
                .await
                .unwrap(),
        );
        repository
            .bootstrap_admin_if_absent(NewAdminAccount {
                account_id: "acc_alice".to_string(),
                login_name: "admin".to_string(),
                password_hash: None,
                display_name: None,
                email: None,
                avatar_url: None,
            })
            .await
            .unwrap();
        let repository: Arc<dyn AgentWebSessionHandoffRepository> = repository;
        (
            directory,
            AgentWebSessionHandoffStore::with_limits(
                repository,
                maximum_entries,
                maximum_entries_per_account,
            ),
        )
    }

    #[tokio::test]
    async fn handoff_is_shared_single_use_and_rejects_tampering_and_expiry() {
        let (_directory, store) = test_store(4, 4).await;
        let issued = store.issue_at("acc_alice", 7, 1_000).await.unwrap();
        let mut tampered = issued.code.clone().into_bytes();
        tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            store
                .consume_at(std::str::from_utf8(&tampered).unwrap(), 1_001)
                .await,
            Err(AgentWebSessionHandoffConsumeError::InvalidOrConsumed)
        );

        let claim = store.consume_at(&issued.code, 1_001).await.unwrap();
        assert_eq!(claim.account_id, "acc_alice");
        assert_eq!(claim.account_auth_version, 7);
        assert_eq!(
            store.consume_at(&issued.code, 1_002).await,
            Err(AgentWebSessionHandoffConsumeError::InvalidOrConsumed)
        );

        let expired = store.issue_at("acc_alice", 7, 2_000).await.unwrap();
        assert_eq!(expired.expires_at, 2_090);
        assert_eq!(
            store.consume_at(&expired.code, expired.expires_at).await,
            Err(AgentWebSessionHandoffConsumeError::Expired)
        );
    }

    #[tokio::test]
    async fn handoff_store_enforces_per_account_capacity_and_prunes_expired_entries() {
        let (_directory, store) = test_store(2, 1).await;
        store.issue_at("acc_alice", 1, 1_000).await.unwrap();
        assert_eq!(
            store.issue_at("acc_alice", 1, 1_001).await.map(|_| ()),
            Err(AgentWebSessionHandoffIssueError::Capacity)
        );
        assert!(store.issue_at("acc_alice", 1, 1_091).await.is_ok());
    }
}
