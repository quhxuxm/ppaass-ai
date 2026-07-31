use super::*;

#[test]
fn stale_stop_hint_cannot_clean_a_new_active_lease_path() {
    let active = lease("new-lease", 42);
    let registry = LeaseRegistry {
        state_path: unique_test_path("registry.json"),
        leases: HashMap::from([(
            active.lease_id.clone(),
            TunSystemLease {
                route_guard: None,
                metadata: active.clone(),
            },
        )]),
    };

    assert!(
        registry
            .route_state_owned_by_another("old-lease", active.route_state_file.as_deref().unwrap())
    );
    assert!(
        registry.dns_state_owned_by_another("old-lease", active.dns_state_file.as_deref().unwrap())
    );
}

#[test]
fn unknown_stop_cannot_touch_a_live_lease_or_global_pf_cleanup() {
    let owner_pid = std::process::id();
    let owner_start_time = process_start_time(owner_pid).unwrap();
    let active = lease("live-lease", owner_pid);
    let state_path = unique_test_path("unknown-stop.json");
    let cleanup_called = Cell::new(false);
    let mut registry = LeaseRegistry {
        state_path: state_path.clone(),
        leases: HashMap::from([(
            active.lease_id.clone(),
            TunSystemLease {
                route_guard: None,
                metadata: active,
            },
        )]),
    };

    assert!(
        !registry
            .stop_owned_with_artifact_cleanup(
                "unknown-lease",
                Some("/tmp/untrusted-routes.json".to_string()),
                Some("/tmp/untrusted-dns.json".to_string()),
                owner_pid,
                owner_start_time,
                |_, _, _| {
                    cleanup_called.set(true);
                    Ok(())
                },
            )
            .unwrap()
    );
    assert!(!cleanup_called.get());
    assert!(registry.leases.contains_key("live-lease"));
    assert!(!state_path.exists());
}

#[test]
fn stale_stop_owner_identity_is_rejected_before_cleanup() {
    let owner_pid = std::process::id();
    let owner_start_time = process_start_time(owner_pid).unwrap();
    let active = lease("owned-lease", owner_pid);
    let state_path = unique_test_path("stale-owner-stop.json");
    let cleanup_called = Cell::new(false);
    let mut registry = LeaseRegistry {
        state_path: state_path.clone(),
        leases: HashMap::from([(
            active.lease_id.clone(),
            TunSystemLease {
                route_guard: None,
                metadata: active,
            },
        )]),
    };
    let stale_start_time = ProcessStartTime {
        unix_secs: owner_start_time.unix_secs.saturating_add(1),
        micros: owner_start_time.micros,
    };

    let error = registry
        .stop_owned_with_artifact_cleanup(
            "owned-lease",
            None,
            None,
            owner_pid,
            stale_start_time,
            |_, _, _| {
                cleanup_called.set(true);
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

    assert!(error.contains("拒绝 StopTun"));
    assert!(!cleanup_called.get());
    assert!(!registry.leases["owned-lease"].metadata.cleanup_requested);
    assert!(!state_path.exists());
}

#[test]
fn matching_stop_owner_identity_can_clean_its_lease() {
    let owner_pid = std::process::id();
    let owner_start_time = process_start_time(owner_pid).unwrap();
    let mut active = lease("owned-lease", owner_pid);
    active.route_state_file = None;
    active.dns_state_file = None;
    let state_path = unique_test_path("matching-owner-stop.json");
    let cleanup_called = Cell::new(false);
    let mut registry = LeaseRegistry {
        state_path: state_path.clone(),
        leases: HashMap::from([(
            active.lease_id.clone(),
            TunSystemLease {
                route_guard: None,
                metadata: active,
            },
        )]),
    };

    assert!(
        registry
            .stop_owned_with_artifact_cleanup(
                "owned-lease",
                None,
                None,
                owner_pid,
                owner_start_time,
                |_, _, _| {
                    cleanup_called.set(true);
                    Ok(())
                },
            )
            .unwrap()
    );
    assert!(cleanup_called.get());
    assert!(registry.leases.is_empty());
    assert!(!state_path.exists());
}

#[test]
fn pf_enable_token_is_persisted_in_lease_registry() {
    let state_path = unique_test_path("pf-token.json");
    let mut metadata = lease("pf-token-lease", std::process::id());
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

    registry
        .set_pf_enable_token("pf-token-lease", Some("token-123".to_string()))
        .unwrap();
    let persisted = load_persisted_leases(&state_path).unwrap();
    assert_eq!(persisted[0].pf_enable_token.as_deref(), Some("token-123"));

    registry.leases.clear();
    registry.persist().unwrap();
    assert!(!state_path.exists());
}

#[test]
fn pf_token_persist_failure_keeps_token_in_memory_for_immediate_rollback() {
    let parent_file = unique_test_path("pf-token-parent-file");
    fs::write(&parent_file, b"not a directory").unwrap();
    let state_path = parent_file.join("leases.json");
    let mut metadata = lease("pf-token-rollback", std::process::id());
    metadata.route_state_file = None;
    metadata.dns_state_file = None;
    let mut registry = LeaseRegistry {
        state_path,
        leases: HashMap::from([(
            metadata.lease_id.clone(),
            TunSystemLease {
                route_guard: None,
                metadata,
            },
        )]),
    };

    assert!(
        registry
            .set_pf_enable_token("pf-token-rollback", Some("token-to-release".to_string()))
            .is_err()
    );
    assert_eq!(
        registry.leases["pf-token-rollback"]
            .metadata
            .pf_enable_token
            .as_deref(),
        Some("token-to-release")
    );

    fs::remove_file(parent_file).unwrap();
}

#[test]
fn helper_info_reports_durable_recovery_protocol_version() {
    let response = TunHelperResponse::HelperInfo {
        protocol_version: TUN_HELPER_PROTOCOL_VERSION,
    };
    let value = serde_json::to_value(response).unwrap();

    assert_eq!(value["type"], "helper_info");
    assert_eq!(value["protocol_version"], 4);
}

#[test]
fn lease_registry_path_is_bound_to_the_socket_name() {
    assert_eq!(
        helper_lease_state_path(Path::new("/var/run/ppaass-ai/tun-helper.sock")),
        PathBuf::from("/var/run/ppaass-ai/tun-helper.sock.leases.json")
    );
}
