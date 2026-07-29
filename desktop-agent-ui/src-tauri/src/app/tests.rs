use std::io::Write;
use std::path::PathBuf;

use super::{agent_auth_state, verified_auth_failure_reason};
use crate::models::{AgentAuthAccount, AgentAuthAccountStatus};
use crate::runtime::AgentRuntime;
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
        .set_authenticated_session(
            AgentAuthAccount {
                username: "alice".to_string(),
                key_version: 7,
                expires_at: Some(1_900_000_000),
            },
            AgentAuthAccountStatus::Expired,
            PathBuf::from("managed/alice.pem"),
            PathBuf::from("managed/proxy.pem"),
            "https://proxy.example.com".to_string(),
        )
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
        .set_authenticated_session(
            AgentAuthAccount {
                username: "bob".to_string(),
                key_version: 2,
                expires_at: None,
            },
            AgentAuthAccountStatus::Active,
            PathBuf::from("managed/bob.pem"),
            PathBuf::from("managed/proxy.pem"),
            "https://proxy.example.com".to_string(),
        )
        .unwrap();
    *runtime.ui_config_path.lock().unwrap() = Some(invalid_config.path().to_path_buf());

    let state = agent_auth_state(&runtime).unwrap();

    assert!(state.authenticated);
    assert_eq!(state.account.unwrap().username, "bob");
    assert_eq!(state.account_status, Some(AgentAuthAccountStatus::Active));
    assert!(state.config.is_none());
}
