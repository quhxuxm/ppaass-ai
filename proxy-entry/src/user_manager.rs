use crate::config::UserConfig;
use crate::error::{ProxyError, Result};
use parking_lot::Mutex;
use protocol::tcp_transport::{tcp_auth_replay_key, tcp_auth_replay_user_key};
use proxy_user_store::UserRepository;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tracing::instrument;

pub struct UserManager {
    repository: Arc<dyn UserRepository>,
    /// Only successfully verified TCP authentication proofs enter this bounded
    /// cache. It makes a signed client nonce a one-shot value inside the
    /// configured timestamp window.
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
    #[instrument(skip(repository))]
    pub fn new(repository: Arc<dyn UserRepository>) -> Self {
        Self {
            repository,
            tcp_auth_replays: Mutex::new(TcpAuthReplayCache::default()),
        }
    }

    #[instrument(skip(self))]
    pub async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        self.repository
            .get_user(username)
            .await
            .map(|user| {
                user.map(|user| UserConfig {
                    username: user.username,
                    public_key_pem: user.public_key_pem,
                    expires_at: user.expires_at.map(|timestamp| timestamp.to_string()),
                    permissions: user.permissions,
                    enabled: user.enabled,
                    key_version: Some(user.key_version),
                })
            })
            .map_err(|error| {
                ProxyError::Configuration(format!("查询用户 Repository 失败：{error}"))
            })
    }

    /// Atomically consume one verified TCP authentication nonce.
    ///
    /// The caller must invoke this only after RSA-PSS verification, otherwise
    /// unauthenticated packets could fill the cache. Capacity exhaustion fails
    /// closed after expired entries have been pruned.
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

#[cfg(test)]
mod tests {
    use super::{MAX_TCP_AUTH_REPLAY_ENTRIES_PER_USER, UserManager};
    use protocol::RsaKeyPair;
    use proxy_user_store::{SqliteUserRepository, UserRepository};
    use std::sync::Arc;
    use tempfile::TempDir;

    #[tokio::test]
    async fn observes_web_changes_from_the_same_sqlite_file() {
        let directory = TempDir::new().unwrap();
        let database_path = directory.path().join("users.sqlite3");
        let web_store = SqliteUserRepository::connect(&database_path).await.unwrap();
        let proxy_store = SqliteUserRepository::connect_read_only(&database_path)
            .await
            .unwrap();
        let repository: Arc<dyn UserRepository> = Arc::new(proxy_store);
        let manager = UserManager::new(repository);
        assert!(manager.get_user("alice").await.unwrap().is_none());

        let public_key = RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        web_store
            .create_user("alice", &public_key, Some(1_893_456_000))
            .await
            .unwrap();

        let user = manager.get_user("alice").await.unwrap().unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.expires_at.as_deref(), Some("1893456000"));
    }

    #[tokio::test]
    async fn verified_tcp_auth_nonce_is_one_shot_and_expires() {
        let directory = TempDir::new().unwrap();
        let repository: Arc<dyn UserRepository> = Arc::new(
            SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
                .await
                .unwrap(),
        );
        let manager = UserManager::new(repository);
        let nonce = [9_u8; 32];

        assert!(manager.claim_tcp_auth_nonce("alice", nonce, 100, 200));
        assert!(!manager.claim_tcp_auth_nonce("alice", nonce, 100, 200));
        assert!(manager.claim_tcp_auth_nonce("bob", nonce, 100, 200));
        assert!(manager.claim_tcp_auth_nonce("alice", nonce, 201, 300));
    }

    #[tokio::test]
    async fn one_user_cannot_exhaust_the_global_tcp_replay_cache() {
        let directory = TempDir::new().unwrap();
        let repository: Arc<dyn UserRepository> = Arc::new(
            SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
                .await
                .unwrap(),
        );
        let manager = UserManager::new(repository);
        for index in 0..MAX_TCP_AUTH_REPLAY_ENTRIES_PER_USER {
            let mut nonce = [0_u8; 32];
            nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
            assert!(manager.claim_tcp_auth_nonce("alice", nonce, 100, 200));
        }
        assert!(!manager.claim_tcp_auth_nonce("alice", [0xff; 32], 100, 200));
        assert!(manager.claim_tcp_auth_nonce("bob", [0xff; 32], 100, 200));
    }
}
