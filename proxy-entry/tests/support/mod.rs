#![allow(dead_code)]

use async_trait::async_trait;
use proxy_entry::config::{ProxyConfig, UserConfig};
use proxy_entry::error::Result;
use proxy_entry::user_manager::AuthorizationProvider;
use std::collections::HashMap;

#[derive(Default)]
pub struct TestAuthorizationProvider {
    users: tokio::sync::RwLock<HashMap<String, UserConfig>>,
}

impl TestAuthorizationProvider {
    pub fn new(users: impl IntoIterator<Item = UserConfig>) -> Self {
        Self {
            users: tokio::sync::RwLock::new(
                users
                    .into_iter()
                    .map(|user| (user.username.clone(), user))
                    .collect(),
            ),
        }
    }

    pub async fn set_user(&self, user: UserConfig) {
        self.users.write().await.insert(user.username.clone(), user);
    }

    pub async fn remove_user(&self, username: &str) {
        self.users.write().await.remove(username);
    }
}

#[async_trait]
impl AuthorizationProvider for TestAuthorizationProvider {
    async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        Ok(self.users.read().await.get(username).cloned())
    }
}

pub fn proxy_config(extra: &str) -> ProxyConfig {
    toml::from_str(&format!(
        r#"
listen_addr = "127.0.0.1:0"
entry_id = "entry-test"
advertised_address = "proxy.example.com:443"
registry_url = "http://127.0.0.1:8797"
registry_control_token_path = "control-token"
{extra}
"#
    ))
    .unwrap()
}
