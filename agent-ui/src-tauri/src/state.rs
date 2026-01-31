//! Application state management

use crate::config::{AgentConfig, AgentState};
use parking_lot::Mutex;
use std::time::Instant;

/// Global application state
pub struct AppState {
    /// Current configuration
    pub config: Mutex<AgentConfig>,
    /// Current agent state
    pub agent_state: Mutex<AgentState>,
    /// Agent start time (for uptime calculation)
    pub start_time: Mutex<Option<Instant>>,
}

impl AppState {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            config: Mutex::new(config),
            agent_state: Mutex::new(AgentState::default()),
            start_time: Mutex::new(None),
        }
    }
}
