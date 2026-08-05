use super::*;
use crate::models::{
    AgentAuthAccount, AGENT_EGRESS_EDIT_PERMISSION, AGENT_PACKET_CAPTURE_PERMISSION,
    AGENT_RUNTIME_THREADS_EDIT_PERMISSION,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AppliedAccountDefaults {
    pub packet_capture: bool,
    pub egress: bool,
    pub runtime: bool,
}

impl AppliedAccountDefaults {
    pub fn any(self) -> bool {
        self.packet_capture || self.egress || self.runtime
    }
}

pub fn built_in_default_config_summary() -> Result<AgentConfigSummary, String> {
    summarize_config(include_str!("../../../../config/agent.toml"))
}

pub fn apply_account_config_defaults(
    summary: &mut AgentConfigSummary,
    account: &AgentAuthAccount,
) -> Result<AppliedAccountDefaults, String> {
    let defaults = built_in_default_config_summary()?;
    let mut applied = AppliedAccountDefaults::default();

    if !account.has_permission(AGENT_PACKET_CAPTURE_PERMISSION)
        && summary.tun_packet_capture_file != defaults.tun_packet_capture_file
    {
        summary
            .tun_packet_capture_file
            .clone_from(&defaults.tun_packet_capture_file);
        applied.packet_capture = true;
    }
    if !account.has_permission(AGENT_EGRESS_EDIT_PERMISSION) {
        apply_egress_defaults(summary, &defaults, &mut applied);
    }
    if !account.has_permission(AGENT_RUNTIME_THREADS_EDIT_PERMISSION) {
        apply_runtime_defaults(summary, &defaults, &mut applied);
    }
    Ok(applied)
}

pub(crate) fn enforce_loaded_config_for_account(
    mut loaded: LoadedAgentConfig,
    account: &AgentAuthAccount,
) -> Result<(LoadedAgentConfig, AppliedAccountDefaults), String> {
    let applied = apply_account_config_defaults(&mut loaded.summary, account)?;
    if applied.any() {
        loaded.raw = merge_config_summary(&loaded.raw, &loaded.summary)?;
    }
    Ok((loaded, applied))
}

pub(crate) fn enforce_config_path_for_account(
    path: &Path,
    account: &AgentAuthAccount,
) -> Result<(LoadedAgentConfig, AppliedAccountDefaults), String> {
    let loaded = load_config_from_path(path)?;
    let (enforced, applied) = enforce_loaded_config_for_account(loaded, account)?;
    if applied.any() {
        let config_path = PathBuf::from(&enforced.path);
        write_config_file(&config_path, &enforced.raw)?;
    }
    Ok((enforced, applied))
}

pub(crate) fn enforce_managed_config_path_for_account(
    path: &Path,
    account: &AgentAuthAccount,
) -> Result<(LoadedAgentConfig, AppliedAccountDefaults), String> {
    enforce_config_path_for_account(path, account)
}

fn apply_egress_defaults(
    summary: &mut AgentConfigSummary,
    defaults: &AgentConfigSummary,
    applied: &mut AppliedAccountDefaults,
) {
    macro_rules! replace_if_different {
        ($field:ident) => {
            if summary.$field != defaults.$field {
                summary.$field.clone_from(&defaults.$field);
                applied.egress = true;
            }
        };
    }
    replace_if_different!(transport_mode);
    replace_if_different!(udp_session_pool_size);
    replace_if_different!(connect_timeout_secs);
    replace_if_different!(compression_mode);
    replace_if_different!(udp_yamux_sessions);
    replace_if_different!(udp_yamux_max_streams_per_session);
    replace_if_different!(udp_yamux_open_stream_timeout_secs);
    replace_if_different!(udp_yamux_keepalive_interval_secs);
    replace_if_different!(udp_yamux_connection_write_timeout_secs);
    replace_if_different!(udp_yamux_stream_window_size_kb);
}

fn apply_runtime_defaults(
    summary: &mut AgentConfigSummary,
    defaults: &AgentConfigSummary,
    applied: &mut AppliedAccountDefaults,
) {
    if summary.log_level != defaults.log_level {
        summary.log_level.clone_from(&defaults.log_level);
        applied.runtime = true;
    }
    if summary.runtime_threads != defaults.runtime_threads {
        summary.runtime_threads = defaults.runtime_threads;
        summary.effective_runtime_threads = defaults.effective_runtime_threads;
        applied.runtime = true;
    }
}
