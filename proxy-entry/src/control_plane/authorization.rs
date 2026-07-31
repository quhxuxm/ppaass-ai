use async_trait::async_trait;

use super::client::RemoteControlPlane;
use crate::{config::UserConfig, error::Result, user_manager::AuthorizationProvider};

#[async_trait]
impl AuthorizationProvider for RemoteControlPlane {
    async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        self.authorization_store.get_user(username).await
    }
}
