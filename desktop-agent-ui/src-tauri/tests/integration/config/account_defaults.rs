use desktop_agent_ui::config::{
    apply_account_config_defaults, built_in_default_config_summary, AppliedAccountDefaults,
};
use desktop_agent_ui::models::{
    AgentAuthAccount, AGENT_EGRESS_EDIT_PERMISSION, AGENT_PACKET_CAPTURE_PERMISSION,
    AGENT_RUNTIME_THREADS_EDIT_PERMISSION,
};

fn account(permissions: &[&str]) -> AgentAuthAccount {
    AgentAuthAccount {
        username: "alice".to_string(),
        display_name: None,
        avatar_url: None,
        role: "user".to_string(),
        permissions: permissions.iter().map(ToString::to_string).collect(),
        key_version: 1,
        expires_at: None,
    }
}

#[test]
fn missing_permissions_restore_all_owned_fields_to_bundled_defaults() {
    let defaults = built_in_default_config_summary().unwrap();
    let mut customized = defaults.clone();
    customized.transport_mode = "tcp".to_string();
    customized.udp_session_pool_size = 8;
    customized.connect_timeout_secs = 999;
    customized.compression_mode = "zstd".to_string();
    customized.udp_yamux_sessions = 99;
    customized.udp_yamux_max_streams_per_session = 999;
    customized.udp_yamux_open_stream_timeout_secs = 88;
    customized.udp_yamux_keepalive_interval_secs = 77;
    customized.udp_yamux_connection_write_timeout_secs = 66;
    customized.udp_yamux_stream_window_size_kb = 555;
    customized.log_level = "trace".to_string();
    customized.runtime_threads = Some(99);
    customized.effective_runtime_threads = 99;
    customized.tun_packet_capture_file = "custom.pcap".to_string();

    let applied = apply_account_config_defaults(&mut customized, &account(&[])).unwrap();

    assert_eq!(
        applied,
        AppliedAccountDefaults {
            packet_capture: true,
            egress: true,
            runtime: true,
        }
    );
    assert_eq!(customized, defaults);
}

#[test]
fn granted_permissions_preserve_owned_custom_values() {
    let defaults = built_in_default_config_summary().unwrap();
    let mut customized = defaults.clone();
    customized.log_level = "trace".to_string();
    customized.tun_packet_capture_file = "custom.pcap".to_string();
    let permissions = [
        AGENT_PACKET_CAPTURE_PERMISSION,
        AGENT_EGRESS_EDIT_PERMISSION,
        AGENT_RUNTIME_THREADS_EDIT_PERMISSION,
    ];

    let applied = apply_account_config_defaults(&mut customized, &account(&permissions)).unwrap();

    assert!(!applied.any());
    assert_eq!(customized.log_level, "trace");
    assert_eq!(customized.tun_packet_capture_file, "custom.pcap");
}
