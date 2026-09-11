#![allow(dead_code)]

use async_trait::async_trait;
use protocol::RsaKeyPair;
use proxy_entry::config::{ProxyConfig, UserConfig};
use proxy_entry::error::Result;
use proxy_entry::user_manager::AuthorizationProvider;
use std::collections::HashMap;
use std::sync::OnceLock;

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
    let mut config: ProxyConfig = toml::from_str(&format!(
        r#"
listen_addr = "127.0.0.1:0"
entry_id = "entry-test"
advertised_address = "proxy.example.com:443"
registry_url = "http://127.0.0.1:8797"
registry_control_token_path = "control-token"
authorization_database_path = "authorization.sqlite3"
{extra}
"#
    ))
    .unwrap();
    config.auth_connect_private_key_path = test_auth_connect_key_path().to_string();
    config
}

fn test_auth_connect_key_path() -> &'static str {
    static PATH: OnceLock<String> = OnceLock::new();
    PATH.get_or_init(|| {
        let key = RsaKeyPair::generate(2048).unwrap();
        let path = std::env::temp_dir().join(format!(
            "ppaass-proxy-entry-test-auth-connect-{}.pem",
            std::process::id()
        ));
        std::fs::write(&path, key.private_key_to_pem().unwrap()).unwrap();
        path.to_string_lossy().into_owned()
    })
}
