use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tauri::path::BaseDirectory;
use tauri::Manager;
use tempfile::Builder;
use toml::Value;
use toml_edit::{value, DocumentMut};

use crate::logging::UiLogBuffer;
use crate::models::{AgentConfigSummary, LoadedAgentConfig};

const BUNDLED_AGENT_CONFIG_PATH: &str = "agent.toml";
// Windows Service must load wintun.dll from the protected installation directory.
// Never deploy executable code into the user-writable Agent data directory.
const BUNDLED_AGENT_SUPPORT_FILES: &[(&str, &str)] = &[];
const LEGACY_BUNDLED_DEMO_KEYS: &[(&str, &str)] = &[
    (
        "keys/user1.pem",
        "f643613d2d534bd85a8ee6022c91a1c526eec013922d1cb178a03e22a9a4f71c",
    ),
    (
        "keys/user2.pem",
        "9a237dc718f468584f094c02482bdef4ca89c1f7ed855a03ac7880e027025288",
    ),
];

// UDP Yamux 保持较小默认值，避免普通 UDP/QUIC 场景创建过多长期外层 TCP。
const DEFAULT_UDP_YAMUX_SESSIONS: u64 = 5;
const DEFAULT_UDP_SESSION_POOL_SIZE: u64 = 4;
const MAX_UDP_SESSION_POOL_SIZE: u64 = 8;

static DEPLOYED_AGENT_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

mod edit;
mod paths;
mod storage;
mod summary;

pub(crate) use edit::*;
pub(crate) use paths::*;
pub(crate) use storage::*;
pub(crate) use summary::*;

#[cfg(test)]
mod tests;
