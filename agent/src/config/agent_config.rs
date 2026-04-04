use crate::direct_access::DirectAccessConfig;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub listen_addr: String,
    pub proxy_addrs: Vec<String>,
    pub username: String,
    pub private_key_path: String,
    #[serde(default = "default_async_runtime_stack_size_mb")]
    pub async_runtime_stack_size_mb: usize,

    #[serde(default = "default_pool_size")]
    pub pool_size: usize,

    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// Maximum age in seconds for a pooled connection.  Connections older than
    /// this are discarded and replaced with a fresh one rather than being used,
    /// preventing failures caused by the proxy's own idle-connection timeout
    /// closing the connection before the agent can use it.
    /// Should be set to a value less than the proxy's `idle_connection_timeout_secs`
    /// (default: 90 seconds, proxy default is 120 seconds).
    #[serde(default = "default_pool_max_connection_age_secs")]
    pub pool_max_connection_age_secs: u64,

    #[serde(default = "default_console_port")]
    pub console_port: Option<u16>,

    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Log directory for file-based logging (improves performance vs console)
    pub log_dir: Option<String>,

    /// Log file name for file-based logging
    #[serde(default = "default_log_file")]
    pub log_file: String,

    /// Maximum number of log lines retained in the TUI buffer
    #[serde(default = "default_log_buffer_lines")]
    pub log_buffer_lines: usize,

    /// Number of Tokio runtime worker threads (defaults to CPU cores)
    #[serde(default)]
    pub runtime_threads: Option<usize>,

    /// Direct access configuration: determines which targets are accessed
    /// directly (bypassing proxy) vs through the proxy tunnel
    #[serde(default)]
    pub direct_access: DirectAccessConfig,
}

fn default_pool_size() -> usize {
    10
}

fn default_connect_timeout_secs() -> u64 {
    30
}

fn default_pool_max_connection_age_secs() -> u64 {
    // Default to 90 seconds — below the proxy's default idle_connection_timeout_secs
    // of 120 seconds.  This ensures pool connections are retired before the proxy
    // closes them, avoiding failed requests due to stale connections.
    90
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_console_port() -> Option<u16> {
    Some(6669)
}

fn default_log_file() -> String {
    "agent.log".to_string()
}

fn default_log_buffer_lines() -> usize {
    1_000
}

fn default_async_runtime_stack_size_mb() -> usize {
    4
}

impl AgentConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: AgentConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}
