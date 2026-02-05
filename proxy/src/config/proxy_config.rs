use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub api_addr: String,
    pub database_path: String,
    pub keys_dir: String,

    #[serde(default)]
    pub console_port: Option<u16>,

    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Log directory for file-based logging (improves performance vs console)
    #[serde(default = "default_log_dir")]
    pub log_dir: String,

    /// Number of Tokio runtime worker threads (defaults to CPU cores)
    #[serde(default)]
    pub runtime_threads: Option<usize>,

    /// Compression mode for data transfer: none, zstd, lz4, gzip
    #[serde(default = "default_compression_mode")]
    pub compression_mode: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_dir() -> String {
    "logs".to_string()
}

fn default_compression_mode() -> String {
    "none".to_string()
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
