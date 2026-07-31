use desktop_agent_ui::models::{
    AgentAdminKeyRequestApproval, AgentAdminKeyRequestRejection, AgentAuthAccount,
    AgentAuthAccountStatus, AgentAuthState, AgentDeviceLoginProgress, AgentKeyRotationRequest,
    AgentLoginRequest, AGENT_PACKET_CAPTURE_PERMISSION,
};

#[test]
fn agent_login_request_rejects_frontend_endpoint_override() {
    let accepted = serde_json::from_value::<AgentLoginRequest>(serde_json::json!({
        "username": "alice",
        "password": "password"
    }));
    assert!(accepted.is_ok());

    let rejected = serde_json::from_value::<AgentLoginRequest>(serde_json::json!({
        "username": "alice",
        "password": "password",
        "proxyRegistryUrl": "https://attacker.example.com"
    }));
    assert!(rejected.is_err());
}

#[test]
fn key_rotation_request_accepts_an_optional_reason_only() {
    let accepted = serde_json::from_value::<AgentKeyRotationRequest>(serde_json::json!({
        "password": "password",
        "reason": "管理员更新自己的连接密钥"
    }));
    assert!(accepted.is_ok());

    let rejected = serde_json::from_value::<AgentKeyRotationRequest>(serde_json::json!({
        "password": "password",
        "username": "attacker",
        "proxyRegistryUrl": "https://attacker.example.com"
    }));
    assert!(rejected.is_err());
}

#[test]
fn admin_key_request_commands_reject_unknown_or_missing_fields() {
    let approval = serde_json::json!({
        "requestId": "kreq_1",
        "expiresAt": 4_000_000_000_i64,
        "proxyAddressIds": ["pxy_1"],
        "reason": "已核实申请用途"
    });
    assert!(serde_json::from_value::<AgentAdminKeyRequestApproval>(approval.clone()).is_ok());
    let mut unexpected = approval;
    unexpected["agentAccessToken"] = serde_json::json!("must-stay-in-rust");
    assert!(serde_json::from_value::<AgentAdminKeyRequestApproval>(unexpected).is_err());
    assert!(serde_json::from_value::<AgentAdminKeyRequestRejection>(
        serde_json::json!({"requestId": "kreq_1", "reason": "请补充说明"})
    )
    .is_ok());
    assert!(serde_json::from_value::<AgentAdminKeyRequestRejection>(
        serde_json::json!({"requestId": "kreq_1", "username": "alice"})
    )
    .is_err());
}

#[test]
fn legacy_persisted_account_gets_safe_role_and_permission_defaults() {
    let account = serde_json::from_value::<AgentAuthAccount>(serde_json::json!({
        "username": "alice",
        "key_version": 7,
        "expires_at": null
    }))
    .unwrap();

    assert_eq!(account.role, "user");
    assert_eq!(account.permissions, ["key.rotate"]);
}

#[test]
fn agent_permissions_are_fail_closed_for_users_and_implicit_for_admins() {
    let mut user = AgentAuthAccount {
        username: "alice".to_string(),
        display_name: None,
        avatar_url: None,
        role: "user".to_string(),
        permissions: Vec::new(),
        key_version: 1,
        expires_at: None,
    };
    assert!(user
        .require_permission(AGENT_PACKET_CAPTURE_PERMISSION)
        .is_err());
    user.permissions
        .push(AGENT_PACKET_CAPTURE_PERMISSION.to_string());
    assert!(user
        .require_permission(AGENT_PACKET_CAPTURE_PERMISSION)
        .is_ok());

    user.role = "admin".to_string();
    user.permissions.clear();
    assert!(user
        .require_permission(AGENT_PACKET_CAPTURE_PERMISSION)
        .is_ok());
}

#[test]
fn auth_state_does_not_serialize_control_plane_endpoint() {
    let state = AgentAuthState {
        authenticated: true,
        account: Some(AgentAuthAccount {
            username: "alice".to_string(),
            display_name: None,
            avatar_url: None,
            role: "user".to_string(),
            permissions: vec!["key.rotate".to_string()],
            key_version: 1,
            expires_at: Some(1_800_000_000),
        }),
        account_status: Some(AgentAuthAccountStatus::Active),
        permission_sync_error: None,
        config: None,
    };

    let serialized = serde_json::to_string(&state).unwrap();
    assert!(!serialized.contains("proxy_registry"));
    assert!(!serialized.contains("attacker.example.com"));
}

#[test]
fn device_login_progress_never_serializes_device_or_private_credentials() {
    let progress = AgentDeviceLoginProgress {
        status: "authorization_pending".to_string(),
        user_code: "ABCD-EFGH-JKMN".to_string(),
        expires_at: 1_800_000_000,
        retry_after_seconds: 5,
        auth_state: None,
    };

    let serialized = serde_json::to_string(&progress).unwrap();
    assert!(serialized.contains("ABCD-EFGH-JKMN"));
    for secret_field in [
        "device_code",
        "private_key",
        "proxy_registry",
        "verification_uri",
    ] {
        assert!(!serialized.contains(secret_field));
    }
}
