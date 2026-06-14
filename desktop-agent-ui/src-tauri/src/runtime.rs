use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use tokio_util::sync::CancellationToken;

use crate::logging::UiLogBuffer;

pub(crate) struct AgentRuntime {
    pub(crate) agent: Mutex<Option<EmbeddedAgent>>,
    pub(crate) config_path: Mutex<Option<PathBuf>>,
    pub(crate) ui_config_path: Mutex<Option<PathBuf>>,
    pub(crate) logs: UiLogBuffer,
    pub(crate) last_error: Arc<Mutex<Option<String>>>,
}

pub(crate) struct EmbeddedAgent {
    pub(crate) shutdown: CancellationToken,
    pub(crate) join: Option<JoinHandle<()>>,
}

impl AgentRuntime {
    pub(crate) fn new() -> Self {
        Self {
            agent: Mutex::new(None),
            config_path: Mutex::new(None),
            ui_config_path: Mutex::new(None),
            logs: UiLogBuffer::new(1200),
            last_error: Arc::new(Mutex::new(None)),
        }
    }
}
