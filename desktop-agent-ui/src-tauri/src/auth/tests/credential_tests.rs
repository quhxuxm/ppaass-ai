use super::*;
use crate::runtime::{AgentPermissionTrust, AuthenticatedAgentSession};

#[test]
fn device_authorization_rejects_malformed_codes_and_cross_origin_verification_urls() {
    assert!(validate_device_code(&"A".repeat(43)).is_ok());
    assert!(validate_device_code("../not-a-device-code").is_err());
    let base = normalize_proxy_web_url("https://proxy.example.com").unwrap();
    assert!(device_verification_url(&base, "/#agent-authorize=ABCD").is_ok());
    assert!(
        device_verification_url(&base, "https://attacker.example.com/#agent-authorize=ABCD")
            .is_err()
    );
}

#[test]
fn validates_matching_key_pair_and_rejects_mismatch() {
    let pair = RsaKeyPair::generate(2048).unwrap();
    let private_key = pair.private_key_to_pem().unwrap();
    let public_key = pair.public_key_to_pem().unwrap();
    assert!(validate_key_pair(&private_key, &public_key).is_ok());

    let other = RsaKeyPair::generate(2048).unwrap();
    assert!(validate_key_pair(&private_key, &other.public_key_to_pem().unwrap()).is_err());
}

#[test]
fn validates_proxy_identity_public_key_strength() {
    let valid = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    assert!(validate_proxy_identity_public_key(&valid).is_ok());
    let weak = RsaKeyPair::generate(1024)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    assert!(validate_proxy_identity_public_key(&weak).is_err());
    assert!(validate_proxy_identity_public_key("not a key").is_err());
}

#[test]
fn managed_key_filename_cannot_escape_credentials_directory() {
    let name = managed_private_key_file_name("../用户/name", 7);
    assert!(!name.contains('/'));
    assert!(!name.contains('\\'));
    assert!(name.ends_with("-v7.pem"));
    assert_eq!(name.len(), "managed-".len() + 64 + "-v7.pem".len());
}

#[test]
fn managed_key_filename_is_bounded_for_maximum_length_username() {
    let username = "x".repeat(128);
    let name = managed_private_key_file_name(&username, i64::MAX);
    assert!(name.len() < 255);
    assert!(!name.contains(&username));
    assert_eq!(name, managed_private_key_file_name(&username, i64::MAX));
}

#[test]
fn cleanup_removes_legacy_username_encoded_managed_keys() {
    let directory = tempfile::tempdir().unwrap();
    let current = managed_private_key_file_name("alice", 2);
    let legacy = "managed-616c696365-v1.pem";
    fs::write(directory.path().join(&current), "current").unwrap();
    fs::write(directory.path().join(legacy), "legacy").unwrap();

    remove_other_managed_private_keys(directory.path(), &current);

    assert!(directory.path().join(&current).is_file());
    assert!(!directory.path().join(legacy).exists());
}

#[test]
fn writes_managed_private_key_with_restricted_permissions() {
    let directory = tempfile::tempdir().unwrap();
    let credentials_dir = directory.path().join("credentials");
    let path =
        write_private_key_to_dir(&credentials_dir, "managed-test-v1.pem", "private").unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "private");
    let replaced =
        write_private_key_to_dir(&credentials_dir, "managed-test-v1.pem", "rotated").unwrap();
    assert_eq!(replaced, path);
    assert_eq!(fs::read_to_string(&path).unwrap(), "rotated");
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&credentials_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn persisted_login_survives_local_expiry_metadata_and_keeps_status() {
    let temp = tempfile::tempdir().unwrap();
    let credentials_dir = temp.path().join("credentials");
    let account = AgentAuthAccount {
        username: "alice".to_string(),
        role: "admin".to_string(),
        permissions: vec!["key.private.read".to_string(), "key.rotate".to_string()],
        key_version: 7,
        // This timestamp is deliberately in the past. It is cached display
        // metadata, not authority for a local automatic logout.
        expires_at: Some(1),
    };
    let user_key = RsaKeyPair::generate(2048).unwrap();
    let proxy_identity = RsaKeyPair::generate(2048).unwrap();
    let private_key_path = write_private_key_to_dir(
        &credentials_dir,
        &managed_private_key_file_name(&account.username, account.key_version),
        &user_key.private_key_to_pem().unwrap(),
    )
    .unwrap();
    write_private_key_to_dir(
        &credentials_dir,
        PROXY_IDENTITY_PUBLIC_KEY_FILE,
        &proxy_identity.public_key_to_pem().unwrap(),
    )
    .unwrap();

    let token =
        super::super::validated_agent_access_token("A".repeat(43), 4_000_000_000, 300).unwrap();
    persist_agent_login_to_dir(
        &credentials_dir,
        &account,
        AgentAuthAccountStatus::Expired,
        Some(&token),
    )
    .unwrap();
    let restored = load_persisted_agent_login_from_dir(&credentials_dir)
        .unwrap()
        .expect("persisted login");

    assert_eq!(restored.account, account);
    assert_eq!(restored.account_status, AgentAuthAccountStatus::Expired);
    assert_eq!(
        restored.agent_access_token.as_ref().unwrap().value.len(),
        43
    );
    assert_eq!(restored.private_key_path, private_key_path);
    assert_eq!(
        restored.proxy_identity_public_key_path,
        credentials_dir.join(PROXY_IDENTITY_PUBLIC_KEY_FILE)
    );
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(credentials_dir.join(super::super::PERSISTED_AGENT_LOGIN_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn persisted_login_requires_untampered_managed_credential_files() {
    let temp = tempfile::tempdir().unwrap();
    let credentials_dir = temp.path().join("credentials");
    let account = AgentAuthAccount {
        username: "alice".to_string(),
        role: "user".to_string(),
        permissions: vec!["key.rotate".to_string()],
        key_version: 1,
        expires_at: None,
    };
    persist_agent_login_to_dir(
        &credentials_dir,
        &account,
        AgentAuthAccountStatus::Active,
        None,
    )
    .unwrap();
    let record_path = credentials_dir.join(super::super::PERSISTED_AGENT_LOGIN_FILE);
    let mut legacy =
        serde_json::from_slice::<serde_json::Value>(&fs::read(&record_path).unwrap()).unwrap();
    let object = legacy.as_object_mut().unwrap();
    object.remove("agent_access_token");
    object.remove("agent_access_token_expires_at");
    object.remove("refresh_after_seconds");
    fs::write(&record_path, serde_json::to_vec(&legacy).unwrap()).unwrap();

    let error = load_persisted_agent_login_from_dir(&credentials_dir)
        .err()
        .expect("missing managed credentials must fail");
    assert!(error.contains("凭据缺失"));
}

#[test]
fn tampered_persisted_role_and_permissions_restore_as_unverified() {
    let temp = tempfile::tempdir().unwrap();
    let credentials_dir = temp.path().join("credentials");
    let account = AgentAuthAccount {
        username: "alice".to_string(),
        role: "user".to_string(),
        permissions: vec!["key.rotate".to_string()],
        key_version: 1,
        expires_at: None,
    };
    let user_key = RsaKeyPair::generate(2048).unwrap();
    let proxy_identity = RsaKeyPair::generate(2048).unwrap();
    write_private_key_to_dir(
        &credentials_dir,
        &managed_private_key_file_name(&account.username, account.key_version),
        &user_key.private_key_to_pem().unwrap(),
    )
    .unwrap();
    write_private_key_to_dir(
        &credentials_dir,
        PROXY_IDENTITY_PUBLIC_KEY_FILE,
        &proxy_identity.public_key_to_pem().unwrap(),
    )
    .unwrap();
    let token =
        super::super::validated_agent_access_token("T".repeat(43), 4_000_000_000, 300).unwrap();
    persist_agent_login_to_dir(
        &credentials_dir,
        &account,
        AgentAuthAccountStatus::Active,
        Some(&token),
    )
    .unwrap();

    let record_path = credentials_dir.join(super::super::PERSISTED_AGENT_LOGIN_FILE);
    let mut record =
        serde_json::from_slice::<serde_json::Value>(&fs::read(&record_path).unwrap()).unwrap();
    record["account"]["role"] = serde_json::json!("admin");
    record["account"]["permissions"] = serde_json::json!([
        "agent.packet_capture",
        "agent.config.view",
        "agent.egress.edit",
        "agent.runtime_threads.edit"
    ]);
    fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();

    let restored = load_persisted_agent_login_from_dir(&credentials_dir)
        .unwrap()
        .unwrap();
    let session = AuthenticatedAgentSession::new(
        restored.account,
        restored.account_status,
        restored.private_key_path,
        restored.proxy_identity_public_key_path,
        "https://proxy.example.com".to_string(),
        restored.agent_access_token,
        AgentPermissionTrust::CachedUnverified,
    );

    assert_eq!(session.account.username, "alice");
    assert_eq!(session.account.role, "user");
    assert!(session.account.permissions.is_empty());
    assert_eq!(
        session.permission_trust,
        AgentPermissionTrust::CachedUnverified
    );
    assert!(session.agent_access_token.is_some());
}
