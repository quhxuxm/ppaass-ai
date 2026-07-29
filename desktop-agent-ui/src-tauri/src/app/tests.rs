use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{
    agent_auth_state, current_ui_config_path, load_agent_config_inner, remember_trusted_ui_config,
    verified_auth_failure_reason,
};
use crate::agent::start_agent_command;
use crate::config::load_config_from_path;
use crate::models::{
    AgentAuthAccount, AgentAuthAccountStatus, AGENT_CONFIG_VIEW_PERMISSION,
    AGENT_EGRESS_EDIT_PERMISSION, AGENT_RUNTIME_THREADS_EDIT_PERMISSION,
};
use crate::runtime::{AgentPermissionTrust, AgentRuntime, AuthenticatedAgentSession};
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
                role: "user".to_string(),
                permissions: vec!["key.rotate".to_string()],
                key_version: 7,
                expires_at: Some(1_900_000_000),
            },
            AgentAuthAccountStatus::Expired,
            PathBuf::from("managed/alice.pem"),
            PathBuf::from("managed/proxy.pem"),
            "https://proxy.example.com".to_string(),
            None,
            AgentPermissionTrust::ServerVerified,
        ))
        .unwrap();
    *runtime.ui_config_path.lock().unwrap() = Some(PathBuf::from("/definitely/missing/agent.toml"));

    let state = agent_auth_state(&runtime).unwrap();

    assert!(state.authenticated);
    assert_eq!(state.account.unwrap().username, "alice");
    assert_eq!(state.account_status, Some(AgentAuthAccountStatus::Expired));
    assert!(state.config.is_none());
    assert!(runtime
        .logs
        .snapshot()
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
                role: "admin".to_string(),
                permissions: vec!["key.rotate".to_string()],
                key_version: 2,
                expires_at: None,
            },
            AgentAuthAccountStatus::Active,
            PathBuf::from("managed/bob.pem"),
            PathBuf::from("managed/proxy.pem"),
            "https://proxy.example.com".to_string(),
            None,
            AgentPermissionTrust::ServerVerified,
        ))
        .unwrap();
    *runtime.ui_config_path.lock().unwrap() = Some(invalid_config.path().to_path_buf());

    let state = agent_auth_state(&runtime).unwrap();

    assert!(state.authenticated);
    assert_eq!(state.account.unwrap().username, "bob");
    assert_eq!(state.account_status, Some(AgentAuthAccountStatus::Active));
    assert!(state.config.is_none());
}

#[test]
fn config_view_cannot_switch_or_start_with_protected_field_changes() {
    let directory = tempfile::tempdir().unwrap();
    let baseline_path = directory.path().join("baseline.toml");
    fs::write(&baseline_path, test_config("127.0.0.1:8080", 2, "info")).unwrap();
    let runtime =
        authenticated_runtime_with_baseline(&baseline_path, &[AGENT_CONFIG_VIEW_PERMISSION]);
    let baseline_path = baseline_path.canonicalize().unwrap();

    for (name, raw, required_permission) in [
        (
            "egress.toml",
            test_config("127.0.0.1:9080", 2, "info"),
            AGENT_EGRESS_EDIT_PERMISSION,
        ),
        (
            "threads.toml",
            test_config("127.0.0.1:8080", 8, "info"),
            AGENT_RUNTIME_THREADS_EDIT_PERMISSION,
        ),
    ] {
        let candidate_path = directory.path().join(name);
        fs::write(&candidate_path, raw).unwrap();

        let load_error =
            load_agent_config_inner(&runtime, Some(candidate_path.to_string_lossy().to_string()))
                .unwrap_err();
        assert!(load_error.contains(required_permission));
        assert_eq!(
            current_ui_config_path(&runtime),
            Some(baseline_path.clone())
        );

        let start_error =
            start_agent_command(&runtime, candidate_path.to_string_lossy().to_string())
                .unwrap_err();
        assert!(start_error.contains(required_permission));
        assert_eq!(
            current_ui_config_path(&runtime),
            Some(baseline_path.clone())
        );
    }
}

#[test]
fn config_view_can_switch_to_candidate_with_unchanged_protected_fields() {
    let directory = tempfile::tempdir().unwrap();
    let baseline_path = directory.path().join("baseline.toml");
    fs::write(&baseline_path, test_config("127.0.0.1:8080", 2, "info")).unwrap();
    let runtime =
        authenticated_runtime_with_baseline(&baseline_path, &[AGENT_CONFIG_VIEW_PERMISSION]);
    let candidate_path = directory.path().join("logging.toml");
    fs::write(&candidate_path, test_config("127.0.0.1:8080", 2, "debug")).unwrap();

    let loaded =
        load_agent_config_inner(&runtime, Some(candidate_path.to_string_lossy().to_string()))
            .unwrap();

    assert_eq!(loaded.summary.log_level, "debug");
    assert_eq!(
        current_ui_config_path(&runtime),
        Some(candidate_path.canonicalize().unwrap())
    );
}

#[test]
fn ipc_config_payload_hides_summary_details_without_view_permission() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("sensitive.toml");
    fs::write(
        &config_path,
        "listen_addr = \"127.0.0.1:10080\"\n\
         proxy_addrs = [\"sensitive.proxy.example:7443\"]\n\
         udp_session_pool_size = 7\n\
         connect_timeout_secs = 9876\n\
         compression_mode = \"sensitive-codec\"\n\
         runtime_threads = 37\n\
         [tun]\n\
         enabled = true\n\
         name = \"sensitive-tun\"\n",
    )
    .unwrap();
    let runtime = authenticated_runtime_with_baseline(&config_path, &[]);

    let loaded = load_agent_config_inner(&runtime, None).unwrap();
    let auth_state = agent_auth_state(&runtime).unwrap();

    for payload in [
        serde_json::to_string(&loaded).unwrap(),
        serde_json::to_string(&auth_state).unwrap(),
    ] {
        assert!(payload.contains("\"tun_enabled\":true"));
        for sensitive in [
            "127.0.0.1:10080",
            "sensitive.proxy.example",
            "sensitive-codec",
            "sensitive-tun",
            "\"runtime_threads\":37",
            "\"connect_timeout_secs\":9876",
            "\"udp_session_pool_size\":7",
        ] {
            assert!(!payload.contains(sensitive));
        }
    }
}

fn authenticated_runtime_with_baseline(path: &Path, permissions: &[&str]) -> AgentRuntime {
    let runtime = AgentRuntime::new();
    runtime
        .set_authenticated_session(AuthenticatedAgentSession::new(
            AgentAuthAccount {
                username: "viewer".to_string(),
                role: "user".to_string(),
                permissions: permissions.iter().map(ToString::to_string).collect(),
                key_version: 1,
                expires_at: None,
            },
            AgentAuthAccountStatus::Active,
            PathBuf::from("managed/viewer.pem"),
            PathBuf::from("managed/proxy.pem"),
            "https://proxy.example.com".to_string(),
            None,
            AgentPermissionTrust::ServerVerified,
        ))
        .unwrap();
    let baseline = load_config_from_path(path).unwrap();
    remember_trusted_ui_config(&runtime, &baseline).unwrap();
    runtime
}

fn test_config(proxy_addr: &str, runtime_threads: usize, log_level: &str) -> String {
    format!(
        "proxy_addrs = [\"{proxy_addr}\"]\nruntime_threads = {runtime_threads}\n\
         log_level = \"{log_level}\"\n"
    )
}
