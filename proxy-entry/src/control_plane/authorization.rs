use async_trait::async_trait;
use tokio::time::Instant;

use super::client::{CachedAuthorization, RemoteControlPlane};
use crate::{config::UserConfig, error::Result, user_manager::AuthorizationProvider};

#[async_trait]
impl AuthorizationProvider for RemoteControlPlane {
    async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        if let Some(cached) = self.cache.read().await.get(username).cloned()
            && Instant::now().duration_since(cached.cached_at) <= self.cache_max_age
        {
            return Ok(cached.value);
        }

        let request_lock = self
            .request_locks
            .entry(username.to_string())
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _request_guard = request_lock.lock().await;
        if let Some(cached) = self.cache.read().await.get(username).cloned()
            && Instant::now().duration_since(cached.cached_at) <= self.cache_max_age
        {
            return Ok(cached.value);
        }

        let result = self.fetch_authorization(username).await;
        if let Ok(value) = &result {
            self.cache.write().await.insert(
                username.to_string(),
                CachedAuthorization {
                    value: value.clone(),
                    cached_at: Instant::now(),
                },
            );
        }
        drop(_request_guard);
        self.request_locks.remove(username);
        result
    }
}
