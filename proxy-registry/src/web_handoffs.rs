use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::{DashMap, mapref::entry::Entry};
use proxy_user_store::WebAccount;
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::auth::random_token;

pub const AGENT_WEB_SESSION_HANDOFF_TTL_SECONDS: i64 = 90;
const AGENT_WEB_SESSION_HANDOFF_CODE_BYTES: usize = 32;
const MAX_ACTIVE_HANDOFFS: usize = 4_096;
const MAX_ACTIVE_HANDOFFS_PER_ACCOUNT: usize = 4;
const HANDOFF_HASH_DOMAIN: &[u8] = b"ppaass-agent-web-session-handoff-v1\0";

#[derive(Clone)]
pub struct AgentWebSessionHandoffStore {
    entries: Arc<DashMap<String, HandoffEntry>>,
    issue_lock: Arc<Mutex<()>>,
    maximum_entries: usize,
    maximum_entries_per_account: usize,
}

#[derive(Clone)]
struct HandoffEntry {
    account_id: String,
    account_auth_version: i64,
    expires_at: i64,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentWebSessionHandoffConsumeError {
    InvalidOrConsumed,
    Expired,
}

impl AgentWebSessionHandoffStore {
    pub fn new() -> Self {
        Self::with_limits(MAX_ACTIVE_HANDOFFS, MAX_ACTIVE_HANDOFFS_PER_ACCOUNT)
    }

    fn with_limits(maximum_entries: usize, maximum_entries_per_account: usize) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            issue_lock: Arc::new(Mutex::new(())),
            maximum_entries: maximum_entries.max(1),
            maximum_entries_per_account: maximum_entries_per_account.max(1),
        }
    }

    pub fn issue(
        &self,
        account: &WebAccount,
    ) -> Result<IssuedAgentWebSessionHandoff, AgentWebSessionHandoffIssueError> {
        self.issue_at(&account.account_id, account.auth_version, now())
    }

    pub fn consume(
        &self,
        code: &str,
    ) -> Result<AgentWebSessionHandoffClaim, AgentWebSessionHandoffConsumeError> {
        self.consume_at(code, now())
    }

    #[cfg(test)]
    pub(crate) fn expire_all_for_test(&self, expires_at: i64) {
        for mut entry in self.entries.iter_mut() {
            entry.expires_at = expires_at;
        }
    }

    fn issue_at(
        &self,
        account_id: &str,
        account_auth_version: i64,
        issued_at: i64,
    ) -> Result<IssuedAgentWebSessionHandoff, AgentWebSessionHandoffIssueError> {
        let _guard = self
            .issue_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, entry| entry.expires_at > issued_at);
        let account_entries = self
            .entries
            .iter()
            .filter(|entry| entry.account_id == account_id)
            .count();
        if self.entries.len() >= self.maximum_entries
            || account_entries >= self.maximum_entries_per_account
        {
            return Err(AgentWebSessionHandoffIssueError::Capacity);
        }

        let expires_at = issued_at.saturating_add(AGENT_WEB_SESSION_HANDOFF_TTL_SECONDS);
        for _ in 0..3 {
            let code = random_token(AGENT_WEB_SESSION_HANDOFF_CODE_BYTES);
            let Some(code_hash) = handoff_code_hash(&code) else {
                continue;
            };
            if let Entry::Vacant(entry) = self.entries.entry(code_hash) {
                entry.insert(HandoffEntry {
                    account_id: account_id.to_string(),
                    account_auth_version,
                    expires_at,
                });
                return Ok(IssuedAgentWebSessionHandoff { code, expires_at });
            }
        }
        Err(AgentWebSessionHandoffIssueError::Capacity)
    }

    fn consume_at(
        &self,
        code: &str,
        consumed_at: i64,
    ) -> Result<AgentWebSessionHandoffClaim, AgentWebSessionHandoffConsumeError> {
        let code_hash =
            handoff_code_hash(code).ok_or(AgentWebSessionHandoffConsumeError::InvalidOrConsumed)?;
        let (_, entry) = self
            .entries
            .remove(&code_hash)
            .ok_or(AgentWebSessionHandoffConsumeError::InvalidOrConsumed)?;
        if entry.expires_at <= consumed_at {
            return Err(AgentWebSessionHandoffConsumeError::Expired);
        }
        Ok(AgentWebSessionHandoffClaim {
            account_id: entry.account_id,
            account_auth_version: entry.account_auth_version,
        })
    }
}

impl Default for AgentWebSessionHandoffStore {
    fn default() -> Self {
        Self::new()
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

    #[test]
    fn handoff_is_single_use_and_rejects_tampering_and_expiry() {
        let store = AgentWebSessionHandoffStore::with_limits(4, 4);
        let issued = store.issue_at("acc_alice", 7, 1_000).unwrap();
        let mut tampered = issued.code.clone().into_bytes();
        tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            store.consume_at(std::str::from_utf8(&tampered).unwrap(), 1_001),
            Err(AgentWebSessionHandoffConsumeError::InvalidOrConsumed)
        );

        let claim = store.consume_at(&issued.code, 1_001).unwrap();
        assert_eq!(claim.account_id, "acc_alice");
        assert_eq!(claim.account_auth_version, 7);
        assert!(matches!(
            store.consume_at(&issued.code, 1_002),
            Err(AgentWebSessionHandoffConsumeError::InvalidOrConsumed)
        ));

        let expired = store.issue_at("acc_alice", 7, 2_000).unwrap();
        assert_eq!(expired.expires_at, 2_090);
        assert!(matches!(
            store.consume_at(&expired.code, expired.expires_at),
            Err(AgentWebSessionHandoffConsumeError::Expired)
        ));
    }

    #[test]
    fn handoff_store_enforces_capacity_and_prunes_expired_entries() {
        let store = AgentWebSessionHandoffStore::with_limits(2, 1);
        store.issue_at("acc_alice", 1, 1_000).unwrap();
        assert_eq!(
            store.issue_at("acc_alice", 1, 1_001).map(|_| ()),
            Err(AgentWebSessionHandoffIssueError::Capacity)
        );
        store.issue_at("acc_bob", 1, 1_001).unwrap();
        assert_eq!(
            store.issue_at("acc_carol", 1, 1_001).map(|_| ()),
            Err(AgentWebSessionHandoffIssueError::Capacity)
        );
        assert!(store.issue_at("acc_carol", 1, 1_091).is_ok());
    }
}
