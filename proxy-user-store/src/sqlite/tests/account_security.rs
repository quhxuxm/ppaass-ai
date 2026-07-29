use super::*;

#[tokio::test]
async fn rotates_legacy_keypair_with_cas_and_upserts_private_key() {
    let (_directory, store) = test_store().await;
    store
        .create_user("legacy-user", &public_key(), None)
        .await
        .unwrap();
    let first = store
        .rotate_keypair(KeyPairRotation {
            username: "legacy-user".to_string(),
            expected_key_version: 1,
            public_key_pem: public_key(),
            encrypted_private_key: b"first-envelope".to_vec(),
        })
        .await
        .unwrap();
    assert_eq!(first.key_version, 2);
    let private = store
        .load_encrypted_private_key("legacy-user")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(private.key_version, 2);
    assert_eq!(private.encrypted_private_key, b"first-envelope");

    let error = store
        .rotate_keypair(KeyPairRotation {
            username: "legacy-user".to_string(),
            expected_key_version: 1,
            public_key_pem: public_key(),
            encrypted_private_key: b"stale-envelope".to_vec(),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        UserRepositoryError::VersionConflict {
            expected: 1,
            actual: 2,
            ..
        }
    ));
    assert_eq!(
        store
            .load_encrypted_private_key("legacy-user")
            .await
            .unwrap()
            .unwrap()
            .encrypted_private_key,
        b"first-envelope"
    );
}

#[tokio::test]
async fn protects_last_active_admin() {
    let (_directory, store) = test_store().await;
    let outcome = store
        .bootstrap_admin_if_none(NewAdminAccount {
            account_id: "admin-one".to_string(),
            login_name: "admin-one".to_string(),
            password_hash: Some("$argon2id$test".to_string()),
            display_name: None,
            email: None,
            avatar_url: None,
        })
        .await
        .unwrap();
    assert!(matches!(outcome, BootstrapOutcome::Created(_)));
    assert!(matches!(
        store
            .update_managed_user(
                "admin-one",
                ManagedUserUpdate {
                    status: Some(AccountStatus::Disabled),
                    ..ManagedUserUpdate::default()
                }
            )
            .await
            .unwrap_err(),
        UserRepositoryError::LastAdmin
    ));
    assert!(matches!(
        store.delete_managed_user("admin-one").await.unwrap_err(),
        UserRepositoryError::LastAdmin
    ));

    store
        .create_managed_user(managed_user(
            "admin-two",
            "admin-two",
            "admin-two-user",
            AccountRole::Admin,
            None,
        ))
        .await
        .unwrap();
    store
        .update_managed_user(
            "admin-one",
            ManagedUserUpdate {
                status: Some(AccountStatus::Disabled),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(store.active_admin_count().await.unwrap(), 1);
}
