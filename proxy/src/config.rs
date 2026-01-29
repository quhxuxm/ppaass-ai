use anyhow::Result;
use common::config::UserConfig;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    #[serde(default = "default_api_listen_addr")]
    pub api_listen_addr: String,

    #[serde(default)]
    pub users: HashMap<String, UserConfig>,

    pub rsa_public_key: String,
    pub rsa_private_key: String,

    #[serde(default = "default_max_connections_per_user")]
    pub max_connections_per_user: usize,

    #[serde(default = "default_session_timeout_secs")]
    pub session_timeout_secs: u64,

    #[serde(default = "default_console_addr")]
    pub tokio_console_addr: String,
}

fn default_listen_addr() -> String {
    "0.0.0.0:8443".to_string()
}

fn default_api_listen_addr() -> String {
    "127.0.0.1:8444".to_string()
}

fn default_max_connections_per_user() -> usize {
    100
}

fn default_session_timeout_secs() -> u64 {
    3600
}

fn default_console_addr() -> String {
    "127.0.0.1:6670".to_string()
}

impl ProxyConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config: {}", e))?;
        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}
