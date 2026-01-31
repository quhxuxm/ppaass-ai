//! Tauri commands for the agent UI

use crate::config::{AgentConfig, AgentState, AgentStatus};
use crate::state::AppState;
use std::fs;
use std::path::PathBuf;
use tauri::State;

fn get_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ppaass")
        .join("agent.toml")
}

/// Get the current agent configuration
#[tauri::command]
pub async fn get_config(state: State<'_, AppState>) -> Result<AgentConfig, String> {
    let config = state.config.lock();
    Ok(config.clone())
}

/// Save the agent configuration
#[tauri::command]
pub async fn save_config(config: AgentConfig, state: State<'_, AppState>) -> Result<(), String> {
    // Update state
    {
        let mut current = state.config.lock();
        *current = config.clone();
    }

    // Save to file
    let config_path = get_config_path();
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {}", e))?;
    }

    let toml_content = toml::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    fs::write(&config_path, toml_content)
        .map_err(|e| format!("Failed to write config file: {}", e))?;

    tracing::info!("Configuration saved to {:?}", config_path);
    Ok(())
}

/// Start the agent
#[tauri::command]
pub async fn start_agent(state: State<'_, AppState>) -> Result<(), String> {
    let mut agent_state = state.agent_state.lock();

    if agent_state.status == AgentStatus::Running {
        return Err("Agent is already running".to_string());
    }

    // In a real implementation, this would spawn the agent process
    // For now, we just update the state
    agent_state.status = AgentStatus::Running;
    agent_state.uptime = 0;
    agent_state.connections = 0;

    // Record start time
    *state.start_time.lock() = Some(std::time::Instant::now());

    tracing::info!("Agent started");
    Ok(())
}

/// Stop the agent
#[tauri::command]
pub async fn stop_agent(state: State<'_, AppState>) -> Result<(), String> {
    let mut agent_state = state.agent_state.lock();

    if agent_state.status != AgentStatus::Running {
        return Err("Agent is not running".to_string());
    }

    // In a real implementation, this would stop the agent process
    agent_state.status = AgentStatus::Stopped;
    agent_state.connections = 0;

    *state.start_time.lock() = None;

    tracing::info!("Agent stopped");
    Ok(())
}

/// Get the current agent state
#[tauri::command]
pub async fn get_agent_state(state: State<'_, AppState>) -> Result<AgentState, String> {
    let mut agent_state = state.agent_state.lock().clone();

    // Update uptime if running
    if agent_state.status == AgentStatus::Running {
        if let Some(start_time) = *state.start_time.lock() {
            agent_state.uptime = start_time.elapsed().as_secs();
        }
    }

    Ok(agent_state)
}

/// Load configuration from file
pub fn load_config_from_file() -> AgentConfig {
    let config_path = get_config_path();

    if config_path.exists() {
        match fs::read_to_string(&config_path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(config) => {
                    tracing::info!("Loaded configuration from {:?}", config_path);
                    return config;
                }
                Err(e) => {
                    tracing::warn!("Failed to parse config file: {}", e);
                }
            },
            Err(e) => {
                tracing::warn!("Failed to read config file: {}", e);
            }
        }
    }

    AgentConfig::default()
}
