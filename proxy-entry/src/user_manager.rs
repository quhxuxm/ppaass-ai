use crate::{config::UserConfig, error::Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use protocol::tcp_transport::{tcp_auth_replay_key, tcp_auth_replay_user_key};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tracing::instrument;

#[async_trait]
pub(crate) trait AuthorizationProvider: Send + Sync {
    async fn get_user(&self, username: &str) -> Result<Option<UserConfig>>;
}

pub struct UserManager {
    provider: Arc<dyn AuthorizationProvider>,
    tcp_auth_replays: Mutex<TcpAuthReplayCache>,
}

const MAX_TCP_AUTH_REPLAY_ENTRIES: usize = 65_536;
const MAX_TCP_AUTH_REPLAY_ENTRIES_PER_USER: usize = 1_024;

#[derive(Default)]
struct TcpAuthReplayCache {
    entries: HashMap<[u8; 32], [u8; 32]>,
    expirations: BTreeMap<i64, Vec<[u8; 32]>>,
    per_user: HashMap<[u8; 32], usize>,
}

impl TcpAuthReplayCache {
    fn prune(&mut self, now: i64) {
        while self
            .expirations
            .first_key_value()
            .is_some_and(|(expiry, _)| *expiry < now)
        {
            let Some((_expiry, keys)) = self.expirations.pop_first() else {
                break;
            };
            for key in keys {
                if let Some(user_key) = self.entries.remove(&key)
                    && let Some(count) = self.per_user.get_mut(&user_key)
                {
                    *count -= 1;
                    if *count == 0 {
                        self.per_user.remove(&user_key);
                    }
                }
            }
        }
    }
}

impl UserManager {
    #[instrument(skip(provider))]
    pub(crate) fn new(provider: impl IntoAuthorizationProvider) -> Self {
        Self {
            provider: provider.into_authorization_provider(),
            tcp_auth_replays: Mutex::new(TcpAuthReplayCache::default()),
        }
    }

    #[instrument(skip(self))]
    pub async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        self.provider.get_user(username).await
    }

    pub(crate) fn claim_tcp_auth_nonce(
        &self,
        username: &str,
        client_nonce: [u8; 32],
        now: i64,
        valid_until: i64,
    ) -> bool {
        let Ok(key) = tcp_auth_replay_key(username, &client_nonce) else {
            return false;
        };
        let Ok(user_key) = tcp_auth_replay_user_key(username) else {
            return false;
        };
        let mut replays = self.tcp_auth_replays.lock();
        replays.prune(now);
        let user_entries = replays.per_user.get(&user_key).copied().unwrap_or(0);
        if replays.entries.contains_key(&key)
            || replays.entries.len() >= MAX_TCP_AUTH_REPLAY_ENTRIES
            || user_entries >= MAX_TCP_AUTH_REPLAY_ENTRIES_PER_USER
        {
            return false;
        }
        let expiry = valid_until.max(now);
        replays.entries.insert(key, user_key);
        replays.expirations.entry(expiry).or_default().push(key);
        *replays.per_user.entry(user_key).or_default() += 1;
        true
    }
}

pub(crate) trait IntoAuthorizationProvider {
    fn into_authorization_provider(self) -> Arc<dyn AuthorizationProvider>;
}

impl<T> IntoAuthorizationProvider for Arc<T>
where
    T: AuthorizationProvider + 'static,
{
    fn into_authorization_provider(self) -> Arc<dyn AuthorizationProvider> {
        self
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestAuthorizationProvider {
    users: tokio::sync::RwLock<HashMap<String, UserConfig>>,
}

#[cfg(test)]
impl TestAuthorizationProvider {
    pub(crate) fn new(users: impl IntoIterator<Item = UserConfig>) -> Self {
        Self {
            users: tokio::sync::RwLock::new(
                users
                    .into_iter()
                    .map(|user| (user.username.clone(), user))
                    .collect(),
            ),
        }
    }

    pub(crate) async fn set_user(&self, user: UserConfig) {
        self.users.write().await.insert(user.username.clone(), user);
    }

    pub(crate) async fn remove_user(&self, username: &str) {
        self.users.write().await.remove(username);
    }
}

#[cfg(test)]
#[async_trait]
impl AuthorizationProvider for TestAuthorizationProvider {
    async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        Ok(self.users.read().await.get(username).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_TCP_AUTH_REPLAY_ENTRIES_PER_USER, TestAuthorizationProvider, UserManager};
    use crate::config::UserConfig;
    use protocol::RsaKeyPair;
    use std::sync::Arc;

    #[tokio::test]
    async fn observes_authorization_provider_changes() {
        let provider = Arc::new(TestAuthorizationProvider::default());
        let manager = UserManager::new(provider.clone());
        assert!(manager.get_user("alice").await.unwrap().is_none());

        provider
            .set_user(UserConfig {
                username: "alice".to_string(),
                public_key_pem: RsaKeyPair::generate(2048)
                    .unwrap()
                    .public_key_to_pem()
                    .unwrap(),
                expires_at: Some("1893456000".to_string()),
                permissions: Vec::new(),
                enabled: true,
                key_version: Some(1),
            })
            .await;
        assert_eq!(
            manager
                .get_user("alice")
                .await
                .unwrap()
                .unwrap()
                .expires_at
                .as_deref(),
            Some("1893456000")
        );
        provider.remove_user("alice").await;
        assert!(manager.get_user("alice").await.unwrap().is_none());
    }

    #[test]
    fn verified_tcp_auth_nonce_is_one_shot_and_expires() {
        let manager = UserManager::new(Arc::new(TestAuthorizationProvider::default()));
        let nonce = [9_u8; 32];
        assert!(manager.claim_tcp_auth_nonce("alice", nonce, 100, 200));
        assert!(!manager.claim_tcp_auth_nonce("alice", nonce, 100, 200));
        assert!(manager.claim_tcp_auth_nonce("bob", nonce, 100, 200));
        assert!(manager.claim_tcp_auth_nonce("alice", nonce, 201, 300));
    }

    #[test]
    fn one_user_cannot_exhaust_the_global_tcp_replay_cache() {
        let manager = UserManager::new(Arc::new(TestAuthorizationProvider::default()));
        for index in 0..MAX_TCP_AUTH_REPLAY_ENTRIES_PER_USER {
            let mut nonce = [0_u8; 32];
            nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
            assert!(manager.claim_tcp_auth_nonce("alice", nonce, 100, 200));
        }
        assert!(!manager.claim_tcp_auth_nonce("alice", [0xff; 32], 100, 200));
        assert!(manager.claim_tcp_auth_nonce("bob", [0xff; 32], 100, 200));
    }
}
