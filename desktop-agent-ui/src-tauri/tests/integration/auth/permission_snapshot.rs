use desktop_agent_ui::auth::{
    apply_permission_snapshot, validated_agent_access_token, AgentPermissionSnapshot,
};
use desktop_agent_ui::models::{AgentAuthAccount, AgentAuthAccountStatus};

fn account(role: &str) -> AgentAuthAccount {
    AgentAuthAccount {
        username: "alice".to_string(),
        display_name: None,
        avatar_url: None,
        role: role.to_string(),
        permissions: vec!["old.permission".to_string()],
        key_version: 7,
        expires_at: Some(4_000_000_000),
    }
}

#[test]
fn snapshot_updates_permissions_without_changing_current_key_material_version() {
    let snapshot = AgentPermissionSnapshot {
        role: "user".to_string(),
        display_name: Some("小爱".to_string()),
        avatar_url: None,
        permissions: Some(vec!["agent.packet_capture".to_string()]),
        proxy_addresses: vec!["proxy.example.com:443".to_string()],
        profile_enabled: Some(true),
        key_version: Some(7),
        expires_at: Some(4_100_000_000),
        account_status: AgentAuthAccountStatus::Active,
        token: validated_agent_access_token("A".repeat(43), 4_000_000_000, 10).unwrap(),
    };
    let (updated, status, warning) = apply_permission_snapshot(&account("user"), &snapshot);
    assert_eq!(updated.permissions, ["agent.packet_capture"]);
    assert_eq!(updated.display_name.as_deref(), Some("小爱"));
    assert_eq!(updated.expires_at, Some(4_100_000_000));
    assert_eq!(status, AgentAuthAccountStatus::Active);
    assert!(warning.is_none());
    assert_eq!(snapshot.token.refresh_after_seconds, 60);
}

#[test]
fn changed_key_version_preserves_local_version_and_marks_account_expired() {
    let snapshot = AgentPermissionSnapshot {
        role: "admin".to_string(),
        display_name: None,
        avatar_url: None,
        permissions: Some(Vec::new()),
        proxy_addresses: vec!["proxy.example.com:443".to_string()],
        profile_enabled: Some(true),
        key_version: Some(8),
        expires_at: None,
        account_status: AgentAuthAccountStatus::Active,
        token: validated_agent_access_token("B".repeat(43), 4_000_000_000, 300).unwrap(),
    };
    let (updated, status, warning) = apply_permission_snapshot(&account("user"), &snapshot);
    assert_eq!(updated.role, "admin");
    assert_eq!(updated.key_version, 7);
    assert_eq!(status, AgentAuthAccountStatus::Expired);
    assert!(warning.unwrap().contains("重新登录"));
}

#[test]
fn missing_profile_clears_stale_user_permissions() {
    let snapshot = AgentPermissionSnapshot {
        role: "user".to_string(),
        display_name: None,
        avatar_url: None,
        permissions: None,
        proxy_addresses: Vec::new(),
        profile_enabled: None,
        key_version: None,
        expires_at: None,
        account_status: AgentAuthAccountStatus::Expired,
        token: validated_agent_access_token("C".repeat(43), 4_000_000_000, 300).unwrap(),
    };
    let (updated, status, warning) = apply_permission_snapshot(&account("user"), &snapshot);
    assert!(updated.permissions.is_empty());
    assert_eq!(status, AgentAuthAccountStatus::Expired);
    assert!(warning.is_none());
}
