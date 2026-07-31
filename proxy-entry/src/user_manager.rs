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
pub trait AuthorizationProvider: Send + Sync {
    async fn get_user(&self, username: &str) -> Result<Option<UserConfig>>;
}

pub struct UserManager {
    provider: Arc<dyn AuthorizationProvider>,
    tcp_auth_replays: Mutex<TcpAuthReplayCache>,
}

const MAX_TCP_AUTH_REPLAY_ENTRIES: usize = 65_536;
pub const MAX_TCP_AUTH_REPLAY_ENTRIES_PER_USER: usize = 1_024;

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
    pub fn new(provider: impl IntoAuthorizationProvider) -> Self {
        Self {
            provider: provider.into_authorization_provider(),
            tcp_auth_replays: Mutex::new(TcpAuthReplayCache::default()),
        }
    }

    #[instrument(skip(self))]
    pub async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        self.provider.get_user(username).await
    }

    pub fn claim_tcp_auth_nonce(
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

pub trait IntoAuthorizationProvider {
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
