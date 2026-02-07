use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabasePoolConfig {
    /// Maximum number of concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Minimum number of connections to maintain
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,

    /// Connection timeout in seconds
    #[serde(default = "default_db_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// Idle timeout in seconds (idle connections are closed)
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// Maximum lifetime of a connection in seconds
    #[serde(default = "default_max_lifetime_secs")]
    pub max_lifetime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub api_addr: String,
    pub database_path: String,
    pub keys_dir: String,

    #[serde(default)]
    pub console_port: Option<u16>,

    /// Enable REST API server for user management and monitoring (default: false)
    #[serde(default)]
    pub enable_api: bool,

    /// Database connection pool configuration
    #[serde(default = "default_db_pool_config")]
    pub db_pool: DatabasePoolConfig,

    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Log directory for file-based logging (improves performance vs console)
    pub log_dir: Option<String>,

    /// Number of Tokio runtime worker threads (defaults to CPU cores)
    #[serde(default)]
    pub runtime_threads: Option<usize>,

    /// Compression mode for data transfer: none, zstd, lz4, gzip
    #[serde(default = "default_compression_mode")]
    pub compression_mode: String,

    #[serde(default = "default_replay_attack_tolerance")]
    pub replay_attack_tolerance: i64,

    #[serde(default)]
    pub forward_mode: bool,

    #[serde(default)]
    pub upstream_proxy_addrs: Option<Vec<String>>,

    #[serde(default)]
    pub upstream_username: Option<String>,

    #[serde(default)]
    pub upstream_private_key_path: Option<String>,

    /// Connection timeout in seconds for upstream proxy connections
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_compression_mode() -> String {
    "none".to_string()
}

fn default_replay_attack_tolerance() -> i64 {
    300
}

fn default_connect_timeout_secs() -> u64 {
    30
}

fn default_max_connections() -> u32 {
    32
}

fn default_min_connections() -> u32 {
    5
}

fn default_db_connect_timeout_secs() -> u64 {
    8
}

fn default_idle_timeout_secs() -> u64 {
    300
}

fn default_max_lifetime_secs() -> u64 {
    3600
}

fn default_db_pool_config() -> DatabasePoolConfig {
    DatabasePoolConfig {
        max_connections: default_max_connections(),
        min_connections: default_min_connections(),
        connect_timeout_secs: default_db_connect_timeout_secs(),
        idle_timeout_secs: default_idle_timeout_secs(),
        max_lifetime_secs: default_max_lifetime_secs(),
    }
}

impl ProxyConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: ProxyConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Get the compression mode as a protocol CompressionMode
    pub fn get_compression_mode(&self) -> protocol::CompressionMode {
        self.compression_mode.parse().unwrap_or_default()
    }
}
