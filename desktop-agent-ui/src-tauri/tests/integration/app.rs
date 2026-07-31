use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use desktop_agent_ui::app::{
    agent_auth_state, current_ui_config_path, load_agent_config_inner, remember_trusted_ui_config,
    verified_auth_failure_reason,
};
use desktop_agent_ui::config::{built_in_default_config_summary, load_config_from_path};
use desktop_agent_ui::models::{AgentAuthAccount, AgentAuthAccountStatus};
use desktop_agent_ui::runtime::{
    AgentPermissionTrust, AgentRuntime, AgentSessionCredentials, AuthenticatedAgentSession,
};
use protocol::AuthFailureCode;

#[test]
fn only_matching_verified_terminal_proxy_states_are_reported() {
    assert_eq!(
        verified_auth_failure_reason(AuthFailureCode::UserExpired, "alice", "alice"),
        Some("user_expired")
    );
    assert_eq!(
        verified_auth_failure_reason(AuthFailureCode::UserDisabled, "alice", "alice"),
        Some("user_disabled")
    );
    assert_eq!(
        verified_auth_failure_reason(AuthFailureCode::Other, "alice", "alice"),
        None
    );
    assert_eq!(
        verified_auth_failure_reason(AuthFailureCode::UserExpired, "old-user", "new-user"),
        None
    );
}

#[test]
fn auth_state_keeps_session_when_config_cannot_be_loaded() {
    let runtime = AgentRuntime::new();
    runtime
        .set_authenticated_session(AuthenticatedAgentSession::new(
            AgentAuthAccount {
                username: "alice".to_string(),
                display_name: None,
                avatar_url: None,
                role: "user".to_string(),
                permissions: vec!["key.rotate".to_string()],
                key_version: 7,
                expires_at: Some(1_900_000_000),
            },
            AgentAuthAccountStatus::Expired,
            vec!["proxy.example.com:443".to_string()],
            AgentSessionCredentials::new(
                PathBuf::from("managed/alice.pem"),
                "https://proxy.example.com".to_string(),
                None,
            ),
            AgentPermissionTrust::ServerVerified,
        ))
        .unwrap();
    runtime
        .set_ui_config_path(PathBuf::from("/definitely/missing/agent.toml"))
        .unwrap();

    let state = agent_auth_state(&runtime).unwrap();

    assert!(state.authenticated);
    assert_eq!(state.account.unwrap().username, "alice");
    assert_eq!(state.account_status, Some(AgentAuthAccountStatus::Expired));
    assert!(state.config.is_none());
    assert!(runtime
        .log_snapshot()
        .iter()
        .any(|line| line.contains("保留当前登录状态")));
}

#[test]
fn auth_state_keeps_session_when_config_cannot_be_parsed() {
    let mut invalid_config = tempfile::NamedTempFile::new().unwrap();
    invalid_config
        .write_all(b"this is not = valid [toml")
        .unwrap();
    let runtime = AgentRuntime::new();
    runtime
        .set_authenticated_session(AuthenticatedAgentSession::new(
            AgentAuthAccount {
                username: "bob".to_string(),
                display_name: None,
                avatar_url: None,
                role: "admin".to_string(),
                permissions: vec!["key.rotate".to_string()],
                key_version: 2,
                expires_at: None,
            },
            AgentAuthAccountStatus::Active,
            vec!["proxy.example.com:443".to_string()],
            AgentSessionCredentials::new(
                PathBuf::from("managed/bob.pem"),
                "https://proxy.example.com".to_string(),
                None,
            ),
            AgentPermissionTrust::ServerVerified,
        ))
        .unwrap();
    runtime
        .set_ui_config_path(invalid_config.path().to_path_buf())
        .unwrap();

    let state = agent_auth_state(&runtime).unwrap();

    assert!(state.authenticated);
    assert_eq!(state.account.unwrap().username, "bob");
    assert_eq!(state.account_status, Some(AgentAuthAccountStatus::Active));
    assert!(state.config.is_none());
}

#[test]
fn missing_permissions_replace_owned_fields_with_bundled_defaults_on_load() {
    let directory = tempfile::tempdir().unwrap();
    let baseline_path = directory.path().join("baseline.toml");
    fs::write(&baseline_path, test_config(2, "info")).unwrap();
    let runtime = authenticated_runtime_with_baseline(&baseline_path, "user", &[]);
    let candidate_path = directory.path().join("candidate.toml");
    fs::write(
        &candidate_path,
        concat!(
            "listen_addr = \"127.0.0.1:1088\"\n",
            "transport_mode = \"tcp\"\n",
            "udp_session_pool_size = 8\n",
            "connect_timeout_secs = 9876\n",
            "compression_mode = \"zstd\"\n",
            "runtime_threads = 37\n",
            "log_level = \"trace\"\n",
            "[tun]\n",
            "enabled = true\n",
            "name = \"custom-tun\"\n",
            "[tun.packet_capture]\n",
            "file = \"custom-sensitive.pcap\"\n",
        ),
    )
    .unwrap();

    let loaded =
        load_agent_config_inner(&runtime, Some(candidate_path.to_string_lossy().to_string()))
            .unwrap();
    let defaults = built_in_default_config_summary().unwrap();

    assert_eq!(loaded.summary.listen_addr, "127.0.0.1:1088");
    assert_eq!(loaded.summary.tun_name, "custom-tun");
    assert_eq!(loaded.summary.transport_mode, defaults.transport_mode);
    assert_eq!(
        loaded.summary.connect_timeout_secs,
        defaults.connect_timeout_secs
    );
    assert_eq!(loaded.summary.log_level, defaults.log_level);
    assert_eq!(
        loaded.summary.tun_packet_capture_file,
        defaults.tun_packet_capture_file
    );
    assert!(loaded.raw.is_empty());
    assert_eq!(
        current_ui_config_path(&runtime),
        Some(candidate_path.canonicalize().unwrap())
    );
}

#[test]
fn admin_can_view_raw_config_without_managed_identity_or_proxy_addresses() {
    let directory = tempfile::tempdir().unwrap();
    let baseline_path = directory.path().join("baseline.toml");
    fs::write(&baseline_path, test_config(2, "info")).unwrap();
    let runtime = authenticated_runtime_with_baseline(&baseline_path, "admin", &[]);
    let candidate_path = directory.path().join("logging.toml");
    fs::write(&candidate_path, test_config(2, "debug")).unwrap();

    let loaded =
        load_agent_config_inner(&runtime, Some(candidate_path.to_string_lossy().to_string()))
            .unwrap();

    assert_eq!(loaded.summary.log_level, "debug");
    assert!(loaded.raw.contains("log_level = \"debug\""));
    assert!(!loaded.raw.contains("proxy.example.com"));
    assert!(!loaded.raw.contains("proxy_addrs"));
    assert_eq!(
        current_ui_config_path(&runtime),
        Some(candidate_path.canonicalize().unwrap())
    );
}

#[test]
fn ordinary_ipc_payload_keeps_safe_summary_and_defaults_restricted_fields() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("sensitive.toml");
    fs::write(
        &config_path,
        "listen_addr = \"127.0.0.1:10080\"\n\
         udp_session_pool_size = 7\n\
         connect_timeout_secs = 9876\n\
         compression_mode = \"sensitive-codec\"\n\
         runtime_threads = 37\n\
         [tun]\n\
         enabled = true\n\
         name = \"sensitive-tun\"\n",
    )
    .unwrap();
    let runtime = authenticated_runtime_with_baseline(&config_path, "user", &[]);

    let loaded = load_agent_config_inner(&runtime, None).unwrap();
    let auth_state = agent_auth_state(&runtime).unwrap();

    for payload in [
        serde_json::to_string(&loaded).unwrap(),
        serde_json::to_string(&auth_state).unwrap(),
    ] {
        assert!(payload.contains("\"tun_enabled\":true"));
        assert!(payload.contains("127.0.0.1:10080"));
        assert!(payload.contains("sensitive-tun"));
        for sensitive in [
            "proxy.example.com",
            "sensitive-codec",
            "\"runtime_threads\":37",
        ] {
            assert!(!payload.contains(sensitive));
        }
    }
}

fn authenticated_runtime_with_baseline(
    path: &Path,
    role: &str,
    permissions: &[&str],
) -> AgentRuntime {
    let runtime = AgentRuntime::new();
    runtime
        .set_authenticated_session(AuthenticatedAgentSession::new(
            AgentAuthAccount {
                username: "viewer".to_string(),
                display_name: None,
                avatar_url: None,
                role: role.to_string(),
                permissions: permissions.iter().map(ToString::to_string).collect(),
                key_version: 1,
                expires_at: None,
            },
            AgentAuthAccountStatus::Active,
            vec!["proxy.example.com:443".to_string()],
            AgentSessionCredentials::new(
                PathBuf::from("managed/viewer.pem"),
                "https://proxy.example.com".to_string(),
                None,
            ),
            AgentPermissionTrust::ServerVerified,
        ))
        .unwrap();
    let baseline = load_config_from_path(path).unwrap();
    remember_trusted_ui_config(&runtime, &baseline).unwrap();
    runtime
}

fn test_config(runtime_threads: usize, log_level: &str) -> String {
    format!(
        "runtime_threads = {runtime_threads}\n\
         log_level = \"{log_level}\"\n"
    )
}

mod server_events;
