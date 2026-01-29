use anyhow::Result;
use common::config::{ConnectionPoolConfig, UserConfig};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    pub proxy_addr: String,

    pub user: UserConfig,

    #[serde(default)]
    pub connection_pool: ConnectionPoolConfig,

    #[serde(default = "default_proxy_public_key")]
    pub proxy_rsa_public_key: String,

    #[serde(default = "default_console_addr")]
    pub tokio_console_addr: String,
}

fn default_listen_addr() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_console_addr() -> String {
    "127.0.0.1:6669".to_string()
}

fn default_proxy_public_key() -> String {
    String::new()
}

impl AgentConfig {
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
