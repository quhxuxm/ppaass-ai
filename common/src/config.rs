use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub username: String,
    pub password: String,
    pub rsa_public_key: String,
    pub rsa_private_key: String,
    #[serde(default)]
    pub bandwidth_limit: Option<u64>, // bytes per second
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolConfig {
    #[serde(default = "default_pool_size")]
    pub max_size: usize,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,
}

fn default_pool_size() -> usize {
    10
}

fn default_idle_timeout() -> u64 {
    300
}

fn default_connection_timeout() -> u64 {
    30
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_size: default_pool_size(),
            idle_timeout_secs: default_idle_timeout(),
            connection_timeout_secs: default_connection_timeout(),
        }
    }
}
