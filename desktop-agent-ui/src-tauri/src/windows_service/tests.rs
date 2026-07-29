use super::*;

use super::*;

#[test]
fn service_handles_capture_status_locally_without_recursive_ipc() {
    let runtime = AgentRuntime::new();

    let response = handle_service_request(&runtime, ServiceRequest::PacketCaptureStatus);

    assert!(response.ok);
    let status = response.packet_capture.expect("capture status");
    assert!(!status.available);
    assert!(!status.enabled);
}

#[test]
fn service_returns_dns_records_from_its_own_agent_process() {
    let runtime = AgentRuntime::new();

    let response = handle_service_request(&runtime, ServiceRequest::DnsRecords);

    assert!(response.ok);
    assert!(response.dns_records.is_some());
}

#[test]
fn service_reports_typed_verified_proxy_account_status() {
    let runtime = AgentRuntime::new();
    runtime
        .set_verified_proxy_auth_status(VerifiedProxyAuthStatus {
            username: "alice".to_string(),
            status: AgentAuthAccountStatus::Expired,
        })
        .unwrap();

    let response = handle_service_request(&runtime, ServiceRequest::State);
    assert_eq!(
        response.auth_status,
        Some(VerifiedProxyAuthStatus {
            username: "alice".to_string(),
            status: AgentAuthAccountStatus::Expired,
        })
    );

    runtime
        .set_verified_proxy_auth_status(VerifiedProxyAuthStatus {
            username: "alice".to_string(),
            status: AgentAuthAccountStatus::Active,
        })
        .unwrap();
    let response = handle_service_request(&runtime, ServiceRequest::State);
    assert_eq!(
        response.auth_status,
        Some(VerifiedProxyAuthStatus {
            username: "alice".to_string(),
            status: AgentAuthAccountStatus::Active,
        })
    );
}

#[test]
fn only_state_changing_service_requests_are_serialized() {
    assert!(service_request_is_mutating(&ServiceRequest::Start {
        config_path: "agent.toml".to_string(),
    }));
    assert!(service_request_is_mutating(&ServiceRequest::Stop));
    assert!(service_request_is_mutating(
        &ServiceRequest::SetPacketCapture { enabled: true }
    ));
    assert!(!service_request_is_mutating(&ServiceRequest::State));
    assert!(!service_request_is_mutating(&ServiceRequest::Traffic));
    assert!(!service_request_is_mutating(&ServiceRequest::DnsRecords));
    assert!(!service_request_is_mutating(
        &ServiceRequest::PacketCaptureStatus
    ));
}

#[test]
fn service_paths_reject_escape_and_accept_managed_app_data_config() {
    assert!(validate_service_relative_path("captures/agent.pcap").is_ok());
    assert!(validate_service_relative_path("../outside.pcap").is_err());
    assert!(validate_service_relative_path(r"C:\Windows\outside.pcap").is_err());
    assert!(validate_service_relative_path(r"\Windows\outside.pcap").is_err());

    let temp = tempfile::tempdir().unwrap();
    let app_data = temp
        .path()
        .join("AppData")
        .join("Roaming")
        .join("com.ppaass.agent");
    fs::create_dir_all(&app_data).unwrap();
    let credentials = temp
        .path()
        .join("AppData")
        .join("Local")
        .join("com.ppaass.agent")
        .join("credentials");
    fs::create_dir_all(&credentials).unwrap();
    let key = credentials.join("managed-616c696365-v1.pem");
    fs::write(&key, "managed test key").unwrap();
    let proxy_identity = credentials.join(MANAGED_PROXY_IDENTITY_PUBLIC_KEY_FILE);
    fs::write(&proxy_identity, "managed proxy identity").unwrap();
    let config = app_data.join("agent.toml");
    let escaped_key = key.to_string_lossy().replace('\\', "\\\\");
    let escaped_proxy_identity = proxy_identity.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        &config,
        format!(
            "username = \"alice\"\nprivate_key_path = \"{escaped_key}\"\n\
                 proxy_identity_public_key_path = \"{escaped_proxy_identity}\"\n\
                 log_dir = \"logs\"\n"
        ),
    )
    .unwrap();

    assert!(validate_service_config_path_for_root(config.to_str().unwrap(), &app_data).is_ok());

    let other_app_data = temp
        .path()
        .join("Other")
        .join("AppData")
        .join("Local")
        .join("com.ppaass.agent");
    fs::create_dir_all(&other_app_data).unwrap();
    assert!(
        validate_service_config_path_for_root(config.to_str().unwrap(), &other_app_data).is_err()
    );

    fs::write(
        &config,
        format!(
            "username = \"alice\"\nprivate_key_path = \"{escaped_key}\"\n\
                 proxy_identity_public_key_path = \"{escaped_proxy_identity}\"\n\
                 log_dir = \"..\\\\outside\"\n"
        ),
    )
    .unwrap();
    assert!(validate_service_config_path_for_root(config.to_str().unwrap(), &app_data).is_err());

    let outside = temp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let linked_capture_dir = app_data.join("linked-captures");
    if std::os::windows::fs::symlink_dir(&outside, &linked_capture_dir).is_ok() {
        assert!(validate_service_managed_path(&app_data, "linked-captures/agent.pcap").is_err());
    }
}

#[test]
fn service_requires_proxy_identity_pin_from_managed_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let app_data = temp
        .path()
        .join("AppData")
        .join("Roaming")
        .join("com.ppaass.agent");
    let credentials = temp
        .path()
        .join("AppData")
        .join("Local")
        .join("com.ppaass.agent")
        .join("credentials");
    fs::create_dir_all(&app_data).unwrap();
    fs::create_dir_all(&credentials).unwrap();

    let private_key = credentials.join("managed-616c696365-v1.pem");
    fs::write(&private_key, "managed test key").unwrap();
    let proxy_identity = credentials.join(MANAGED_PROXY_IDENTITY_PUBLIC_KEY_FILE);
    fs::write(&proxy_identity, "managed proxy identity").unwrap();
    let outside_dir = temp.path().join("outside");
    fs::create_dir_all(&outside_dir).unwrap();
    let outside_identity = outside_dir.join(MANAGED_PROXY_IDENTITY_PUBLIC_KEY_FILE);
    fs::write(&outside_identity, "unmanaged proxy identity").unwrap();

    let config = app_data.join("agent.toml");
    let escaped_private_key = private_key.to_string_lossy().replace('\\', "\\\\");
    let escaped_proxy_identity = proxy_identity.to_string_lossy().replace('\\', "\\\\");
    let escaped_outside_identity = outside_identity.to_string_lossy().replace('\\', "\\\\");

    fs::write(
        &config,
        format!("username = \"alice\"\nprivate_key_path = \"{escaped_private_key}\"\n"),
    )
    .unwrap();
    assert!(
        validate_service_config_path_for_root(config.to_str().unwrap(), &app_data)
            .unwrap_err()
            .contains("缺少托管 Proxy 身份公钥")
    );

    fs::write(
        &config,
        format!(
            "username = \"alice\"\nprivate_key_path = \"{escaped_private_key}\"\n\
                 proxy_identity_public_key_path = \"{escaped_outside_identity}\"\n"
        ),
    )
    .unwrap();
    assert!(validate_service_config_path_for_root(config.to_str().unwrap(), &app_data).is_err());

    fs::write(
        &config,
        format!(
            "username = \"alice\"\nprivate_key_path = \"{escaped_private_key}\"\n\
                 proxy_identity_public_key_path = \"{escaped_proxy_identity}\"\n"
        ),
    )
    .unwrap();
    assert!(validate_service_config_path_for_root(config.to_str().unwrap(), &app_data).is_ok());
}

#[test]
fn service_command_extracts_pinned_config_root() {
    let command = concat!(
        r#""C:\Program Files\PPAASS\PPAASS Agent.exe" --ppaass-agent-service "#,
        r#"--ppaass-service-config-root "C:\Users\Alice\AppData\Local\com.ppaass.agent""#
    );
    assert_eq!(
        extract_command_argument_path(command, SERVICE_CONFIG_ROOT_ARG).as_deref(),
        Some(r"C:\Users\Alice\AppData\Local\com.ppaass.agent")
    );
    assert_eq!(
        extract_command_argument_path(
            "--ppaass-service-config-root C:\\AgentData --ppaass-agent-service",
            SERVICE_CONFIG_ROOT_ARG,
        )
        .as_deref(),
        Some(r"C:\AgentData")
    );
    assert!(extract_command_argument_path(command, "--missing").is_none());
    assert!(normalized_path_is_within(
        Path::new(r"C:\Users\Alice\AppData\Local\com.ppaass.agent\captures"),
        Path::new(r"c:\users\alice\appdata\local\com.ppaass.agent")
    ));
    assert!(!normalized_path_is_within(
        Path::new(r"C:\Users\Alice\AppData\Local\com.ppaass.agent-copy"),
        Path::new(r"C:\Users\Alice\AppData\Local\com.ppaass.agent")
    ));
    assert!(sc_service_is_auto_start(
        "START_TYPE         : 2   AUTO_START"
    ));
    assert!(!sc_service_is_auto_start(
        "START_TYPE         : 3   DEMAND_START"
    ));
}

#[test]
fn service_request_encoder_rejects_oversized_payloads() {
    let request = ServiceRequest::Start {
        config_path: "a".repeat(MAX_SERVICE_IPC_REQUEST_BYTES as usize),
    };
    assert!(encode_service_request(&request, &"a".repeat(SERVICE_SESSION_TOKEN_HEX_LEN)).is_err());
}

#[test]
fn service_request_envelope_requires_a_well_formed_secret() {
    let request = ServiceRequest::State;
    assert!(encode_service_request(&request, "short").is_err());

    let token = "ab".repeat(SERVICE_SESSION_TOKEN_BYTES);
    let encoded = encode_service_request(&request, &token).unwrap();
    let envelope = serde_json::from_slice::<ServiceRequestEnvelope>(&encoded).unwrap();
    assert_eq!(envelope.auth_token, token);
    assert!(matches!(envelope.request, ServiceRequest::State));
    assert!(constant_time_token_eq(token.as_bytes(), token.as_bytes()));
    assert!(!constant_time_token_eq(
        token.as_bytes(),
        "cd".repeat(SERVICE_SESSION_TOKEN_BYTES).as_bytes()
    ));
}

#[test]
fn service_session_survives_ui_process_exit_and_ignores_local_expiry_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let config_root = temp
        .path()
        .join("AppData")
        .join("Roaming")
        .join("com.ppaass.agent");
    fs::create_dir_all(&config_root).unwrap();
    let session_path = service_session_file_path_for_root(&config_root).unwrap();
    fs::create_dir_all(session_path.parent().unwrap()).unwrap();
    let token = "ab".repeat(SERVICE_SESSION_TOKEN_BYTES);

    let active = ServiceSessionAuthorization {
        version: SERVICE_SESSION_FILE_VERSION,
        token: token.clone(),
        _legacy_ui_process_id: None,
        _legacy_ui_process_creation_time: None,
        _legacy_expires_at: None,
    };
    fs::write(&session_path, serde_json::to_vec(&active).unwrap()).unwrap();
    let loaded = read_service_session_authorization(&session_path).unwrap();
    assert_eq!(loaded.token, token);

    let exited_legacy_ui = ServiceSessionAuthorization {
        version: SERVICE_SESSION_FILE_VERSION,
        token: token.clone(),
        _legacy_ui_process_id: Some(u32::MAX),
        _legacy_ui_process_creation_time: Some(1),
        _legacy_expires_at: None,
    };
    fs::write(
        &session_path,
        serde_json::to_vec(&exited_legacy_ui).unwrap(),
    )
    .unwrap();
    assert!(read_service_session_authorization(&session_path).is_ok());

    let legacy_locally_expired = ServiceSessionAuthorization {
        version: SERVICE_SESSION_FILE_VERSION,
        token,
        _legacy_ui_process_id: Some(u32::MAX),
        _legacy_ui_process_creation_time: Some(1),
        _legacy_expires_at: Some(1),
    };
    fs::write(
        &session_path,
        serde_json::to_vec(&legacy_locally_expired).unwrap(),
    )
    .unwrap();
    assert!(read_service_session_authorization(&session_path).is_ok());
}

#[test]
fn desired_running_state_is_atomic_strict_and_independent_of_local_time() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join(SERVICE_DESIRED_STATE_FILE_NAME);
    let alice = ServiceLoginBinding {
        username: "alice".to_string(),
        key_version: 7,
    };

    assert_eq!(read_service_desired_state(&path).unwrap(), None);

    persist_service_desired_state(&path, Some(&alice)).unwrap();
    assert_eq!(
        read_service_desired_state(&path).unwrap(),
        Some(alice.clone())
    );

    persist_service_desired_state(&path, None).unwrap();
    assert_eq!(read_service_desired_state(&path).unwrap(), None);

    fs::write(
            &path,
            br#"{"version":1,"desired_running":true,"username":"alice","key_version":7,"expires_at":1}"#,
        )
        .unwrap();
    assert!(read_service_desired_state(&path).is_err());

    fs::write(
        &path,
        br#"{"version":2,"desired_running":true,"username":"alice","key_version":7}"#,
    )
    .unwrap();
    assert!(read_service_desired_state(&path).is_err());

    fs::write(&path, br#"{"version":1,"desired_running":true}"#).unwrap();
    assert!(read_service_desired_state(&path).is_err());
}
