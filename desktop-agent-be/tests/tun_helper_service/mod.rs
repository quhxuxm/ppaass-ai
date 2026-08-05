#![cfg(target_os = "macos")]

use common::tun_control::{
    TUN_HELPER_PROTOCOL_VERSION, TunHelperRequest, TunHelperResponse, TunStartRequest,
    tun_helper_dns_state_path, tun_helper_route_state_path,
};
use desktop_agent_be::tun_handler::helper_service::*;
use std::cell::Cell;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn lease(id: &str, owner_pid: u32) -> PersistedTunLease {
    PersistedTunLease {
        lease_id: id.to_string(),
        owner_pid,
        owner_start_time: process_start_time(owner_pid),
        cleanup_requested: false,
        route_state_file: Some(format!("/tmp/{id}-routes.json")),
        dns_state_file: Some(format!("/tmp/{id}-dns.json")),
        pf_enable_token: None,
        route_recovery: None,
    }
}

fn route_recovery() -> PersistedRouteRecovery {
    PersistedRouteRecovery {
        request: TunStartRequest {
            name: "ppaass-test".to_string(),
            ipv4: "198.18.0.1/15".to_string(),
            ipv6: None,
            mtu: 1500,
            proxy_addrs: vec!["127.0.0.1:8080".to_string()],
            proxy_dns: true,
            proxy_bind_interface: None,
            route_state_file: Some("/tmp/test-routes.json".to_string()),
            dns_state_file: Some("/tmp/test-dns.json".to_string()),
        },
        actual_name: "utun42".to_string(),
        tun_if_index: 42,
        tun_ipv4: Ipv4Addr::new(198, 18, 0, 1),
        dns_capture_target: Ipv4Addr::new(198, 18, 0, 2),
        proxy_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    }
}

fn unique_test_path(name: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "ppaass-helper-{name}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn persisted_lease_survives_helper_restart_round_trip() {
    let path = unique_test_path("leases.json");
    let mut recoverable = lease("lease-b", 42);
    recoverable.route_recovery = Some(route_recovery());
    let expected = vec![recoverable, lease("lease-a", 41)];
    persist_lease_state(
        &path,
        &PersistedLeaseState {
            version: HELPER_LEASE_STATE_VERSION,
            leases: expected.clone(),
        },
    )
    .unwrap();

    let loaded = load_persisted_leases(&path).unwrap();
    let mut expected = expected;
    for lease in &mut expected {
        lease.clear_runtime_proxy_addresses();
    }
    assert_eq!(
        serde_json::to_value(loaded).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert!(
        !fs::read_to_string(&path)
            .unwrap()
            .contains("127.0.0.1:8080")
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_file(path).unwrap();
}

#[test]
fn legacy_lease_without_process_start_time_is_readable_but_not_live() {
    let metadata: PersistedTunLease = serde_json::from_str(
        r#"{
            "lease_id":"legacy",
            "owner_pid":42,
            "route_state_file":null,
            "dns_state_file":null
        }"#,
    )
    .unwrap();

    assert_eq!(metadata.owner_start_time, None);
    assert!(!lease_owner_is_alive(&metadata));
}

#[test]
fn lease_owner_identity_rejects_pid_reuse() {
    let pid = std::process::id();
    let current_start_time = process_start_time(pid).expect("current process start time");
    let mut metadata = lease("identity", pid);
    assert!(lease_owner_is_alive(&metadata));

    metadata.owner_start_time = Some(ProcessStartTime {
        unix_secs: current_start_time.unix_secs.saturating_add(1),
        micros: current_start_time.micros,
    });
    assert!(!lease_owner_is_alive(&metadata));
}

#[test]
fn restart_metadata_keeps_route_recovery_without_server_address() {
    let mut metadata = lease("redacted", 42);
    metadata.route_recovery = Some(route_recovery());
    metadata.clear_runtime_proxy_addresses();
    let recovery = metadata.route_recovery.unwrap();
    let value = serde_json::to_value(&recovery).unwrap();

    assert_eq!(value["request"]["ipv4"], "198.18.0.1/15");
    assert_eq!(value["request"]["proxy_dns"], true);
    assert_eq!(value["request"]["proxy_addrs"], serde_json::json!([]));
    assert_eq!(value["actual_name"], "utun42");
    assert_eq!(value["tun_if_index"], 42);
    assert_eq!(value["proxy_ips"][0], "127.0.0.1");
}

#[test]
fn start_request_state_paths_are_confined_to_the_helper_directory() {
    let registry = LeaseRegistry {
        state_path: unique_test_path("trusted/helper.sock.leases.json"),
        leases: HashMap::new(),
    };
    let (trusted_route, trusted_dns) = registry.trusted_state_paths();
    let mut request = route_recovery().request;
    request.route_state_file = None;
    request.dns_state_file = Some(String::new());

    let confined = registry.confine_start_request(request).unwrap();

    assert_eq!(
        confined.route_state_file.as_deref(),
        Some(trusted_route.to_string_lossy().as_ref())
    );
    assert_eq!(
        confined.dns_state_file.as_deref(),
        Some(trusted_dns.to_string_lossy().as_ref())
    );

    let mut escaped = route_recovery().request;
    escaped.route_state_file = Some("/etc/ppaass-overwrite.json".to_string());
    let error = registry
        .confine_start_request(escaped)
        .unwrap_err()
        .to_string();
    assert!(error.contains("状态路径越界"));
    assert!(error.contains("/etc/ppaass-overwrite.json"));
}

#[test]
fn persisted_lease_recovery_rejects_top_level_and_nested_untrusted_paths() {
    let socket = Path::new("/var/run/ppaass-ai/tun-helper.sock");
    let trusted_route = tun_helper_route_state_path(socket);
    let trusted_dns = tun_helper_dns_state_path(socket);
    let mut metadata = lease("trusted", std::process::id());
    metadata.route_state_file = Some(trusted_route.to_string_lossy().into_owned());
    metadata.dns_state_file = Some(trusted_dns.to_string_lossy().into_owned());
    let mut recovery = route_recovery();
    recovery.request.route_state_file = metadata.route_state_file.clone();
    recovery.request.dns_state_file = metadata.dns_state_file.clone();
    metadata.route_recovery = Some(recovery);

    validate_persisted_lease_state_paths(&metadata, &trusted_route, &trusted_dns).unwrap();

    metadata.route_state_file = Some("/tmp/untrusted-routes.json".to_string());
    assert!(
        validate_persisted_lease_state_paths(&metadata, &trusted_route, &trusted_dns)
            .unwrap_err()
            .to_string()
            .contains("状态路径不受信任")
    );

    metadata.route_state_file = Some(trusted_route.to_string_lossy().into_owned());
    metadata
        .route_recovery
        .as_mut()
        .unwrap()
        .request
        .dns_state_file = Some("/tmp/untrusted-nested-dns.json".to_string());
    assert!(
        validate_persisted_lease_state_paths(&metadata, &trusted_route, &trusted_dns)
            .unwrap_err()
            .to_string()
            .contains("嵌套路由恢复路径")
    );
}

#[test]
fn lease_metadata_is_durable_before_route_install_starts() {
    let state_path = unique_test_path("stage-before-install.json");
    let observed_path = state_path.clone();
    let metadata = lease("pending", std::process::id());
    let mut registry = LeaseRegistry {
        state_path,
        leases: HashMap::new(),
    };

    registry
        .stage_before(metadata, || {
            let staged = load_persisted_leases(&observed_path)?;
            assert_eq!(staged.len(), 1);
            assert_eq!(staged[0].lease_id, "pending");
            Ok(())
        })
        .unwrap();

    registry.leases.remove("pending");
    registry.persist().unwrap();
    assert!(!observed_path.exists());
}

#[test]
fn cleanup_request_rejects_a_live_agent_lease() {
    let mut metadata = lease("live", std::process::id());
    metadata.route_state_file = None;
    metadata.dns_state_file = None;
    let mut registry = LeaseRegistry {
        state_path: unique_test_path("live-cleanup.json"),
        leases: HashMap::from([(
            metadata.lease_id.clone(),
            TunSystemLease {
                route_guard: None,
                metadata,
            },
        )]),
    };

    let error = registry
        .cleanup_orphans_for("upgrade")
        .unwrap_err()
        .to_string();
    assert!(error.contains("helper busy"));
    assert!(registry.leases.contains_key("live"));
}

#[test]
fn cleanup_failure_keeps_durable_retry_metadata() {
    let state_path = unique_test_path("cleanup-retry.json");
    let mut metadata = lease("cleanup-retry", std::process::id());
    metadata.route_state_file = None;
    metadata.dns_state_file = None;
    metadata.pf_enable_token = Some("durable-token".to_string());
    let expected_owner_start_time = metadata.owner_start_time;
    let mut registry = LeaseRegistry {
        state_path: state_path.clone(),
        leases: HashMap::from([(
            metadata.lease_id.clone(),
            TunSystemLease {
                route_guard: None,
                metadata,
            },
        )]),
    };

    let error = registry
        .stop_with_artifact_cleanup("cleanup-retry", None, None, |_, _, token| {
            assert_eq!(token, Some("durable-token"));
            anyhow::bail!("injected PF flush failure")
        })
        .unwrap_err()
        .to_string();

    assert!(error.contains("injected PF flush failure"));
    let retained = registry.leases.get("cleanup-retry").unwrap();
    assert_eq!(retained.metadata.owner_pid, std::process::id());
    assert_eq!(
        retained.metadata.owner_start_time,
        expected_owner_start_time
    );
    assert!(retained.metadata.cleanup_requested);
    assert_eq!(
        retained.metadata.pf_enable_token.as_deref(),
        Some("durable-token")
    );
    let persisted = load_persisted_leases(&state_path).unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].lease_id, "cleanup-retry");
    assert_eq!(persisted[0].owner_pid, std::process::id());
    assert_eq!(persisted[0].owner_start_time, expected_owner_start_time);
    assert!(persisted[0].cleanup_requested);
    assert_eq!(
        persisted[0].pf_enable_token.as_deref(),
        Some("durable-token")
    );

    fs::remove_file(state_path).unwrap();
}

#[test]
fn successful_cleanup_durably_removes_lease_metadata() {
    let state_path = unique_test_path("cleanup-success.json");
    let mut metadata = lease("cleanup-success", std::process::id());
    metadata.route_state_file = None;
    metadata.dns_state_file = None;
    let mut registry = LeaseRegistry {
        state_path: state_path.clone(),
        leases: HashMap::from([(
            metadata.lease_id.clone(),
            TunSystemLease {
                route_guard: None,
                metadata,
            },
        )]),
    };
    registry.persist().unwrap();

    assert!(
        registry
            .stop_with_artifact_cleanup("cleanup-success", None, None, |_, _, _| Ok(()))
            .unwrap()
    );
    assert!(registry.leases.is_empty());
    assert!(!state_path.exists());
}

#[test]
fn old_stop_request_deserializes_without_recovery_hints() {
    let request: TunHelperRequest =
        serde_json::from_str(r#"{"type":"stop_tun","lease_id":"legacy"}"#).unwrap();

    match request {
        TunHelperRequest::StopTun {
            lease_id,
            route_state_file,
            dns_state_file,
        } => {
            assert_eq!(lease_id, "legacy");
            assert_eq!(route_state_file, None);
            assert_eq!(dns_state_file, None);
        }
        other => panic!("unexpected request: {other:?}"),
    }
}

#[test]
fn stop_request_serializes_restart_recovery_hints() {
    let request = TunHelperRequest::StopTun {
        lease_id: "lease-1".to_string(),
        route_state_file: Some("/state/routes.json".to_string()),
        dns_state_file: Some("/state/dns.json".to_string()),
    };
    let value = serde_json::to_value(request).unwrap();

    assert_eq!(value["type"], "stop_tun");
    assert_eq!(value["lease_id"], "lease-1");
    assert_eq!(value["route_state_file"], "/state/routes.json");
    assert_eq!(value["dns_state_file"], "/state/dns.json");
}

mod stop;
