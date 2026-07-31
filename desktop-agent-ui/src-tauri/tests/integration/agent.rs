use common::tun_control::{TUN_HELPER_DNS_STATE_FILE_NAME, TUN_HELPER_ROUTE_STATE_FILE_NAME};
use desktop_agent_be::PacketCaptureController;
use desktop_agent_ui::agent::*;
use desktop_agent_ui::runtime::AgentRuntime;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn formal_agent_config() -> desktop_agent_be::config::AgentConfig {
    let raw = format!(
        "username = \"test-user\"\nprivate_key_path = \"keys/test-user.pem\"\n{}",
        include_str!("../../../../config/agent.toml")
    );
    toml::from_str(&raw).expect("formal Agent config")
}

#[test]
fn missing_or_empty_state_files_resolve_under_the_agent_base_directory() {
    let mut config = formal_agent_config();
    let base_dir = tempfile::tempdir().unwrap();
    config.tun.route_state_file = None;
    config.tun.dns_state_file = Some("   ".to_string());

    normalize_agent_config_paths(&mut config, base_dir.path());

    assert_eq!(
        config.tun.route_state_file.as_deref(),
        Some(
            base_dir
                .path()
                .join(TUN_HELPER_ROUTE_STATE_FILE_NAME)
                .to_string_lossy()
                .as_ref()
        )
    );
    assert_eq!(
        config.tun.dns_state_file.as_deref(),
        Some(
            base_dir
                .path()
                .join(TUN_HELPER_DNS_STATE_FILE_NAME)
                .to_string_lossy()
                .as_ref()
        )
    );
}

#[test]
fn configured_state_files_preserve_absolute_paths_and_resolve_relative_paths() {
    let base_dir = tempfile::tempdir().unwrap();
    let absolute = base_dir.path().join("absolute-routes.json");

    assert_eq!(
        resolve_agent_state_path(
            base_dir.path(),
            Some(absolute.to_string_lossy().as_ref()),
            TUN_HELPER_ROUTE_STATE_FILE_NAME,
        ),
        absolute.to_string_lossy()
    );
    assert_eq!(
        resolve_agent_state_path(
            base_dir.path(),
            Some("state/custom-dns.json"),
            TUN_HELPER_DNS_STATE_FILE_NAME,
        ),
        base_dir
            .path()
            .join("state/custom-dns.json")
            .to_string_lossy()
    );
}

#[test]
fn runtime_capture_defaults_off_and_toggles_and_clears_without_replacing_agent() {
    let runtime = AgentRuntime::new();
    let path = std::env::temp_dir().join(format!(
        "ppaass-runtime-capture-{}-{}.pcap",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let controller = PacketCaptureController::new(path.clone());
    runtime
        .install_packet_capture_controller(controller.clone())
        .unwrap();

    let before = packet_capture_runtime_status(&runtime).unwrap();
    assert!(before.available);
    assert!(!before.enabled);

    let enabled = set_packet_capture_runtime_enabled(&runtime, true).unwrap();
    assert!(enabled.enabled);
    assert!(runtime.packet_capture_enabled());
    assert!(controller.is_enabled());

    let cleared = clear_packet_capture_runtime(&runtime, None).unwrap();
    assert!(cleared.enabled);
    assert_eq!(fs::metadata(&path).unwrap().len(), 24);

    let disabled = set_packet_capture_runtime_enabled(&runtime, false).unwrap();
    assert!(!disabled.enabled);
    assert!(!runtime.packet_capture_enabled());
    fs::remove_file(path).unwrap();
}
