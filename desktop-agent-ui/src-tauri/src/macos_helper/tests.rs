use super::*;
use std::thread;

fn helper_response_server(
    mut stream: UnixStream,
    response: serde_json::Value,
) -> thread::JoinHandle<serde_json::Value> {
    thread::spawn(move || {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).unwrap();
        let mut payload = vec![0u8; u32::from_be_bytes(len_buf) as usize];
        stream.read_exact(&mut payload).unwrap();

        let response = serde_json::to_vec(&response).unwrap();
        stream.write_all(&[1]).unwrap();
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&response).unwrap();
        serde_json::from_slice(&payload).unwrap()
    })
}

#[test]
fn cleanup_request_sends_known_route_and_dns_state_before_restart() {
    let directory = tempfile::tempdir().unwrap();
    let route_path = directory.path().join("route state.json");
    let dns_path = directory.path().join("dns state.json");
    let (mut client, server_stream) = UnixStream::pair().unwrap();
    let server = helper_response_server(server_stream, serde_json::json!({ "type": "ok" }));

    let response = exchange_macos_tun_helper_request(
        &mut client,
        &TunHelperRequest::CleanupStale {
            route_state_file: Some(route_path.to_string_lossy().into_owned()),
            dns_state_file: Some(dns_path.to_string_lossy().into_owned()),
        },
    )
    .unwrap();
    assert!(matches!(response, TunHelperResponse::Ok));

    let request = server.join().unwrap();
    assert_eq!(request["type"], "cleanup_stale");
    assert_eq!(
        request["route_state_file"],
        route_path.to_string_lossy().as_ref()
    );
    assert_eq!(
        request["dns_state_file"],
        dns_path.to_string_lossy().as_ref()
    );
}

#[test]
fn helper_version_handshake_uses_explicit_protocol_version() {
    let (mut client, server_stream) = UnixStream::pair().unwrap();
    let server = helper_response_server(
        server_stream,
        serde_json::json!({
            "type": "helper_info",
            "protocol_version": TUN_HELPER_PROTOCOL_VERSION
        }),
    );

    let response =
        exchange_macos_tun_helper_request(&mut client, &TunHelperRequest::GetHelperInfo).unwrap();
    assert!(matches!(
        response,
        TunHelperResponse::HelperInfo { protocol_version }
            if protocol_version == TUN_HELPER_PROTOCOL_VERSION
    ));
    assert_eq!(server.join().unwrap()["type"], "get_helper_info");
}

#[test]
fn cleanup_request_fails_closed_when_old_helper_rejects_it() {
    let directory = tempfile::tempdir().unwrap();
    let (mut client, server_stream) = UnixStream::pair().unwrap();
    let server = helper_response_server(
        server_stream,
        serde_json::json!({ "type": "error", "message": "lease is busy" }),
    );

    let response = exchange_macos_tun_helper_request(
        &mut client,
        &TunHelperRequest::CleanupStale {
            route_state_file: Some(
                directory
                    .path()
                    .join("routes.json")
                    .to_string_lossy()
                    .into_owned(),
            ),
            dns_state_file: Some(
                directory
                    .path()
                    .join("dns.json")
                    .to_string_lossy()
                    .into_owned(),
            ),
        },
    )
    .unwrap();

    let error = validate_macos_tun_helper_cleanup_response(response).unwrap_err();
    assert!(error.contains("lease is busy"));
    let _ = server.join().unwrap();
}

#[test]
fn existing_state_files_cover_route_dns_and_lease_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let route_path = directory.path().join("tun-routes.json");
    let dns_path = directory.path().join("tun-dns.json");
    let lease_path = directory.path().join("helper.sock.leases.json");
    fs::write(&route_path, br#"{"routes":[{"destination":"0.0.0.0"}]}"#).unwrap();
    fs::write(&dns_path, b"{}").unwrap();
    fs::write(&lease_path, b"{}").unwrap();
    let state_paths = MacosTunHelperStatePaths {
        route: route_path,
        dns: dns_path,
        lease: lease_path,
    };

    let existing = existing_macos_tun_helper_state_files(&state_paths).unwrap();

    assert_eq!(existing.len(), 3);
    assert!(existing.iter().any(|item| item.contains("路由状态")));
    assert!(existing.iter().any(|item| item.contains("DNS 状态")));
    assert!(existing
        .iter()
        .any(|item| item.contains("helper lease 状态")));
}

#[test]
fn install_script_guards_route_state_and_boots_out_before_replacing_binary() {
    let script = macos_tun_helper_install_script(
        Path::new("/Applications/PPAASS Agent.app/Contents/MacOS/ppaass"),
        "/var/run/ppaass-ai/tun-helper.sock",
        501,
        "info",
        Path::new("/Users/test/Library/Application Support/PPAASS/tun-routes.json"),
        Path::new("/Users/test/Library/Application Support/PPAASS/tun-dns.json"),
        Path::new("/var/run/ppaass-ai/tun-helper.sock.leases.json"),
    );

    let guard = script
            .find(
                "if [ -e \"$route_state_path\" ] || [ -e \"$dns_state_path\" ] || [ -e \"$lease_state_path\" ]",
            )
            .expect("route state guard");
    let bootout = script
        .find("/bin/launchctl bootout system \"$plist_path\"")
        .expect("launchd bootout");
    let install = script
        .find("/usr/bin/install -m 0755 \"$source_path\" \"$install_path\"")
        .expect("binary install");

    assert!(guard < bootout);
    assert!(bootout < install);
    assert!(script.contains("exit 73"));
}

#[test]
fn detects_launchd_pid_without_accepting_zero_or_unrelated_fields() {
    assert!(launchd_print_has_pid(
        "state = running\n\tpid = 1234\n\tlast exit code = 0\n"
    ));
    assert!(!launchd_print_has_pid(
        "state = waiting\n\tpid = 0\n\tlast exit code = 1234\n"
    ));
}

#[test]
fn parses_macos_route_interface_and_matches_dynamic_utun_names() {
    assert_eq!(
        parse_macos_route_interface("   route to: 1.1.1.1\ninterface: utun12\nflags: <UP,DONE>\n")
            .as_deref(),
        Some("utun12")
    );
    assert!(tun_interface_matches("utun12", "utun8"));
    assert!(tun_interface_matches("ppaass-tun", "ppaass-tun"));
    assert!(!tun_interface_matches("en0", "utun8"));
}

#[test]
fn helper_state_paths_are_confined_to_the_socket_directory() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../agent.toml");
    let mut config =
        desktop_agent_be::config::AgentConfig::load(&config_path).expect("local config");
    config.tun.macos_helper_socket = directory
        .path()
        .join("helper.sock")
        .to_string_lossy()
        .into_owned();
    config.tun.route_state_file = Some("/tmp/caller-controlled-routes.json".to_string());
    config.tun.dns_state_file = Some("/tmp/caller-controlled-dns.json".to_string());

    let paths = macos_tun_helper_state_paths(&config_path, &config).unwrap();

    assert_eq!(paths.route, directory.path().join("tun-routes.json"));
    assert_eq!(paths.dns, directory.path().join("tun-dns.json"));

    config.tun.macos_helper_socket = "relative/helper.sock".to_string();
    assert!(macos_tun_helper_state_paths(&config_path, &config)
        .unwrap_err()
        .contains("必须使用绝对路径"));
}

#[test]
fn helper_lease_state_path_matches_service_registry_path() {
    assert_eq!(
        macos_tun_helper_lease_state_path(Path::new("/var/run/ppaass-ai/tun-helper.sock")),
        Path::new("/var/run/ppaass-ai/tun-helper.sock.leases.json")
    );
}
