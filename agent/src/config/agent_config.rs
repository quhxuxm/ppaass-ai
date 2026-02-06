use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub listen_addr: String,
    pub proxy_addrs: Vec<String>,
    pub username: String,
    pub private_key_path: String,

    #[serde(default = "default_pool_size")]
    pub pool_size: usize,

    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    #[serde(default)]
    pub console_port: Option<u16>,

    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Log directory for file-based logging (improves performance vs console)
    pub log_dir: Option<String>,

    /// Number of Tokio runtime worker threads (defaults to CPU cores)
    #[serde(default)]
    pub runtime_threads: Option<usize>,
}

fn default_pool_size() -> usize {
    10
}

fn default_connect_timeout_secs() -> u64 {
    30
}

fn default_log_level() -> String {
    "info".to_string()
}

impl AgentConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: AgentConfig = toml::from_str(&content)?;
        Ok(config)
    }
}
