use protocol::RsaKeyPair;
use proxy_registry::store::{
    AccountRole, AccountStatus, NewManagedUser, NewProxyAddress, NewUser, ProxyAddressRepository,
    UserOrigin,
};
use proxy_registry::{
    AccountRepository, PrivateKeyCipher, SqliteFilePermissions, SqliteUserRepository,
    ensure_key_encryption_binding, registry_instance_id, select_database_file_permissions,
    validate_listen_address,
};
use tempfile::TempDir;

#[test]
fn requires_explicit_opt_in_for_non_loopback_http() {
    let loopback = "127.0.0.1:8787".parse().unwrap();
    let remote = "0.0.0.0:8787".parse().unwrap();

    assert!(validate_listen_address(loopback, false).is_ok());
    assert!(validate_listen_address(remote, false).is_err());
    assert!(validate_listen_address(remote, true).is_ok());
}

#[test]
fn derives_a_stable_default_instance_id_from_the_listen_port() {
    let listen = "127.0.0.1:8788".parse().unwrap();
    assert_eq!(
        registry_instance_id(listen).unwrap().as_ref(),
        "registry-8788"
    );
}

#[test]
fn database_group_modes_can_be_enabled_by_cli_or_service_environment() {
    assert_eq!(
        select_database_file_permissions(
            false,
            None,
            SqliteFilePermissions::OwnerReadWriteGroupRead,
        ),
        SqliteFilePermissions::OwnerOnly
    );
    assert_eq!(
        select_database_file_permissions(
            false,
            Some(false),
            SqliteFilePermissions::OwnerReadWriteGroupRead,
        ),
        SqliteFilePermissions::OwnerOnly
    );
    assert_eq!(
        select_database_file_permissions(
            true,
            Some(false),
            SqliteFilePermissions::OwnerReadWriteGroupRead,
        ),
        SqliteFilePermissions::OwnerReadWriteGroupRead
    );
    assert_eq!(
        select_database_file_permissions(false, Some(true), SqliteFilePermissions::OwnerAndGroup,),
        SqliteFilePermissions::OwnerAndGroup
    );
}

#[tokio::test]
async fn key_binding_migrates_existing_envelopes_and_rejects_the_wrong_secret() {
    let directory = TempDir::new().unwrap();
    let store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
        .await
        .unwrap();
    let correct =
        PrivateKeyCipher::new("correct-test-master-secret-with-at-least-32-bytes").unwrap();
    let wrong = PrivateKeyCipher::new("wrong-test-master-secret-with-at-least-32-bytes").unwrap();
    let public_key = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    store
        .create_proxy_address(NewProxyAddress {
            proxy_address_id: "pxy_main_test".to_string(),
            label: "Main test proxy".to_string(),
            address: "127.0.0.1:8080".to_string(),
            enabled: true,
        })
        .await
        .unwrap();
    store
        .create_managed_user(NewManagedUser {
            account_id: "acc_alice".to_string(),
            login_name: "alice".to_string(),
            password_hash: Some("$argon2id$test".to_string()),
            role: AccountRole::User,
            status: AccountStatus::Active,
            display_name: None,
            email: None,
            avatar_url: None,
            profile: NewUser::new("alice", public_key, UserOrigin::Admin),
            encrypted_private_key: correct.encrypt("alice", 1, "private-pem").unwrap(),
            external_identity: None,
            proxy_address_ids: vec!["pxy_main_test".to_string()],
            created_by: None,
            audit_reason: None,
        })
        .await
        .unwrap();

    assert!(ensure_key_encryption_binding(&store, &wrong).await.is_err());
    assert!(
        store
            .key_encryption_binding()
            .await
            .unwrap()
            .verifier
            .is_none()
    );

    ensure_key_encryption_binding(&store, &correct)
        .await
        .unwrap();
    let verifier = store
        .key_encryption_binding()
        .await
        .unwrap()
        .verifier
        .unwrap();
    correct.verify_verifier(&verifier).unwrap();
    assert!(ensure_key_encryption_binding(&store, &wrong).await.is_err());
}
