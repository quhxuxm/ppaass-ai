use std::path::PathBuf;

use zeroize::Zeroizing;

use super::{
    AgentPermissionTrust, AgentRuntime, AgentSessionCredentials, AuthenticatedAgentSession,
};
use crate::auth::validated_agent_access_token;
use crate::models::{
    AgentAdminKeyRequest, AgentAdminKeyRequestInbox, AgentAuthAccount, AgentAuthAccountStatus,
    AGENT_EGRESS_EDIT_PERMISSION, AGENT_PACKET_CAPTURE_PERMISSION,
};

#[test]
fn device_authorization_cancellation_and_generation_check_are_fail_closed() {
    let runtime = AgentRuntime::new();
    let challenge = runtime
        .set_pending_device_authorization(
            Zeroizing::new("A".repeat(43)),
            "https://proxy.example.com".to_string(),
            PathBuf::from("agent.toml"),
            "ABCD-EFGH-JKMN".to_string(),
            1_800_000_000,
            5,
        )
        .unwrap();

    assert!(!runtime
        .take_pending_device_authorization_if(challenge.id + 1)
        .unwrap());
    assert_eq!(
        runtime.pending_device_authorization().unwrap().unwrap().id,
        challenge.id
    );
    runtime.cancel_pending_device_authorization().unwrap();
    assert!(runtime.pending_device_authorization().unwrap().is_none());
    assert!(!runtime
        .take_pending_device_authorization_if(challenge.id)
        .unwrap());
}

#[test]
fn admin_inbox_compares_request_ids_and_removes_decisions() {
    let runtime = AgentRuntime::new();
    let first = admin_inbox(&["kreq_1"]);
    let (_, new_ids) = runtime
        .replace_admin_key_request_inbox(first.clone())
        .unwrap();
    assert_eq!(new_ids, ["kreq_1"]);

    let (_, new_ids) = runtime.replace_admin_key_request_inbox(first).unwrap();
    assert!(new_ids.is_empty());

    let (_, new_ids) = runtime
        .replace_admin_key_request_inbox(admin_inbox(&["kreq_1", "kreq_2"]))
        .unwrap();
    assert_eq!(new_ids, ["kreq_2"]);
    let update = runtime.remove_admin_key_request("kreq_1").unwrap();
    assert_eq!(update.inbox.requests[0].request_id, "kreq_2");

    runtime
        .set_authenticated_session(AuthenticatedAgentSession::new(
            account("admin", &[]),
            AgentAuthAccountStatus::Active,
            managed_proxy_addresses(),
            AgentSessionCredentials::new(
                PathBuf::from("private.pem"),
                PathBuf::from("proxy.pem"),
                "https://proxy.example.com".to_string(),
                Some(token("A")),
            ),
            AgentPermissionTrust::ServerVerified,
        ))
        .unwrap();
    assert!(runtime
        .admin_key_request_inbox()
        .unwrap()
        .requests
        .is_empty());
}

#[test]
fn tampered_cached_admin_permissions_are_fail_closed_until_server_sync() {
    let runtime = AgentRuntime::new();
    runtime
        .set_authenticated_session(AuthenticatedAgentSession::new(
            account(
                "admin",
                &[
                    AGENT_PACKET_CAPTURE_PERMISSION,
                    AGENT_EGRESS_EDIT_PERMISSION,
                ],
            ),
            AgentAuthAccountStatus::Active,
            managed_proxy_addresses(),
            AgentSessionCredentials::new(
                PathBuf::from("private.pem"),
                PathBuf::from("proxy.pem"),
                "https://proxy.example.com".to_string(),
                Some(token("A")),
            ),
            AgentPermissionTrust::CachedUnverified,
        ))
        .unwrap();

    let restored = runtime.authenticated_session().unwrap().unwrap();
    assert_eq!(restored.account.role, "user");
    assert!(restored.account.permissions.is_empty());
    assert_eq!(
        restored.permission_trust,
        AgentPermissionTrust::CachedUnverified
    );
    assert!(restored.agent_access_token.is_some());
}

#[test]
fn successful_sync_restores_server_verified_role_and_permissions() {
    let runtime = AgentRuntime::new();
    runtime
        .set_authenticated_session(AuthenticatedAgentSession::new(
            account("admin", &[AGENT_PACKET_CAPTURE_PERMISSION]),
            AgentAuthAccountStatus::Active,
            managed_proxy_addresses(),
            AgentSessionCredentials::new(
                PathBuf::from("private.pem"),
                PathBuf::from("proxy.pem"),
                "https://proxy.example.com".to_string(),
                Some(token("A")),
            ),
            AgentPermissionTrust::CachedUnverified,
        ))
        .unwrap();

    let synced = runtime
        .update_authenticated_session_from_sync(
            "alice",
            &"A".repeat(43),
            account(
                "admin",
                &[
                    AGENT_PACKET_CAPTURE_PERMISSION,
                    AGENT_EGRESS_EDIT_PERMISSION,
                ],
            ),
            AgentAuthAccountStatus::Active,
            managed_proxy_addresses(),
            token("B"),
        )
        .unwrap()
        .unwrap();

    assert_eq!(synced.account.role, "admin");
    assert_eq!(
        synced.account.permissions,
        [
            AGENT_PACKET_CAPTURE_PERMISSION,
            AGENT_EGRESS_EDIT_PERMISSION
        ]
    );
    assert_eq!(
        synced.permission_trust,
        AgentPermissionTrust::ServerVerified
    );
}

#[test]
fn sync_errors_and_stale_tokens_preserve_the_authenticated_session() {
    let runtime = AgentRuntime::new();
    let account = account("user", &[AGENT_PACKET_CAPTURE_PERMISSION]);
    runtime
        .set_authenticated_session(AuthenticatedAgentSession::new(
            account.clone(),
            AgentAuthAccountStatus::Active,
            managed_proxy_addresses(),
            AgentSessionCredentials::new(
                PathBuf::from("private.pem"),
                PathBuf::from("proxy.pem"),
                "https://proxy.example.com".to_string(),
                Some(token("A")),
            ),
            AgentPermissionTrust::CachedUnverified,
        ))
        .unwrap();
    runtime
        .set_permission_sync_error(Some("暂时无法同步".to_string()))
        .unwrap();
    assert!(runtime
        .update_authenticated_session_from_sync(
            "alice",
            &"C".repeat(43),
            AgentAuthAccount {
                permissions: Vec::new(),
                ..account
            },
            AgentAuthAccountStatus::Disabled,
            managed_proxy_addresses(),
            token("B"),
        )
        .unwrap()
        .is_none());
    let preserved = runtime.authenticated_session().unwrap().unwrap();
    assert!(preserved.account.permissions.is_empty());
    assert_eq!(preserved.account_status, AgentAuthAccountStatus::Active);
    assert_eq!(
        preserved.permission_trust,
        AgentPermissionTrust::CachedUnverified
    );
    assert!(preserved.agent_access_token.is_some());
    assert_eq!(
        runtime.permission_sync_error().unwrap(),
        Some("暂时无法同步".to_string())
    );
}

fn managed_proxy_addresses() -> Vec<String> {
    vec!["proxy.example.com:443".to_string()]
}

fn account(role: &str, permissions: &[&str]) -> AgentAuthAccount {
    AgentAuthAccount {
        username: "alice".to_string(),
        role: role.to_string(),
        permissions: permissions.iter().map(ToString::to_string).collect(),
        key_version: 3,
        expires_at: None,
    }
}

fn token(prefix: &str) -> crate::auth::AgentAccessToken {
    validated_agent_access_token(prefix.repeat(43), 4_000_000_000, 300).unwrap()
}

fn admin_inbox(request_ids: &[&str]) -> AgentAdminKeyRequestInbox {
    AgentAdminKeyRequestInbox {
        requests: request_ids
            .iter()
            .map(|request_id| AgentAdminKeyRequest {
                request_id: (*request_id).to_string(),
                username: "alice".to_string(),
                display_name: None,
                email: None,
                request_message: None,
                kind: "initial".to_string(),
                requested_at: 1_800_000_000,
                proxy_address_ids: Vec::new(),
            })
            .collect(),
        proxy_addresses: Vec::new(),
    }
}
