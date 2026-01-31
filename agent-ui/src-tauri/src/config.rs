//! Agent configuration types shared between UI and agent

use serde::{Deserialize, Serialize};

/// Agent configuration that can be edited through the UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// The address the agent listens on
    pub listen_address: String,
    /// The address of the proxy server
    pub proxy_address: String,
    /// Username for authentication
    pub username: String,
    /// Connection pool size
    pub pool_size: u32,
    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,
    /// Path to the private key file
    pub private_key_path: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1:1080".to_string(),
            proxy_address: "127.0.0.1:8080".to_string(),
            username: String::new(),
            pool_size: 10,
            log_level: "info".to_string(),
            private_key_path: String::new(),
        }
    }
}

/// Agent runtime status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Running,
    Stopped,
    Error,
}

/// Agent runtime state including statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    /// Current status
    pub status: AgentStatus,
    /// Number of active connections
    pub connections: u32,
    /// Uptime in seconds
    pub uptime: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            status: AgentStatus::Stopped,
            connections: 0,
            uptime: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}
