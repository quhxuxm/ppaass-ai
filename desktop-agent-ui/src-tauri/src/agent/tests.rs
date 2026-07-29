use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn missing_or_empty_state_files_resolve_under_the_agent_base_directory() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../agent.toml");
    let mut config =
        desktop_agent_be::config::AgentConfig::load(&config_path).expect("local config");
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
    *runtime.agent.lock().unwrap() = Some(EmbeddedAgent {
        shutdown: CancellationToken::new(),
        join: None,
        packet_capture: controller.clone(),
    });

    let before = packet_capture_runtime_status(&runtime).unwrap();
    assert!(before.available);
    assert!(!before.enabled);

    let enabled = set_packet_capture_runtime_enabled(&runtime, true).unwrap();
    assert!(enabled.enabled);
    assert!(runtime.packet_capture_enabled.load(Ordering::Acquire));
    let agent_controller = runtime
        .agent
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .packet_capture
        .clone();
    assert!(agent_controller.is_enabled());

    let cleared = clear_packet_capture_runtime(&runtime, None).unwrap();
    assert!(cleared.enabled);
    assert_eq!(fs::metadata(&path).unwrap().len(), 24);

    let disabled = set_packet_capture_runtime_enabled(&runtime, false).unwrap();
    assert!(!disabled.enabled);
    assert!(!runtime.packet_capture_enabled.load(Ordering::Acquire));
    fs::remove_file(path).unwrap();
}
