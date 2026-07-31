use std::path::PathBuf;
use std::sync::atomic::Ordering;

use tokio_util::sync::CancellationToken;

use super::{AgentRuntime, EmbeddedAgent};

impl AgentRuntime {
    pub fn set_ui_config_path(&self, path: PathBuf) -> Result<(), String> {
        *self
            .ui_config_path
            .lock()
            .map_err(|_| "UI 配置路径状态锁已损坏".to_string())? = Some(path);
        Ok(())
    }

    pub fn log_snapshot(&self) -> Vec<String> {
        self.logs.snapshot()
    }

    pub fn install_packet_capture_controller(
        &self,
        packet_capture: desktop_agent_be::PacketCaptureController,
    ) -> Result<(), String> {
        *self
            .agent
            .lock()
            .map_err(|_| "进程状态锁已损坏".to_string())? = Some(EmbeddedAgent {
            shutdown: CancellationToken::new(),
            join: None,
            packet_capture,
        });
        Ok(())
    }

    pub fn packet_capture_enabled(&self) -> bool {
        self.packet_capture_enabled.load(Ordering::Acquire)
    }
}
