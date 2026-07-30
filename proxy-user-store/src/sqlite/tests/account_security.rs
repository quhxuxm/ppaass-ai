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
async fn protects_root_admin_but_allows_other_admins_to_be_deleted() {
    let (_directory, store) = test_store().await;
    let outcome = store
        .bootstrap_admin_if_absent(NewAdminAccount {
            account_id: "admin-one".to_string(),
            login_name: "admin".to_string(),
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
        UserRepositoryError::RootAdminProtected
    ));
    assert!(matches!(
        store
            .update_managed_user(
                "admin-one",
                ManagedUserUpdate {
                    role: Some(AccountRole::User),
                    ..ManagedUserUpdate::default()
                }
            )
            .await
            .unwrap_err(),
        UserRepositoryError::RootAdminProtected
    ));
    assert!(matches!(
        store.delete_managed_user("admin-one").await.unwrap_err(),
        UserRepositoryError::RootAdminProtected
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
            "admin-two",
            ManagedUserUpdate {
                status: Some(AccountStatus::Disabled),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(store.active_admin_count().await.unwrap(), 1);
    store.delete_managed_user("admin-two").await.unwrap();
    assert!(
        store
            .get_account_by_id("admin-two")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn bootstrap_root_admin_is_not_suppressed_by_an_existing_admin() {
    let (_directory, store) = test_store().await;
    let first = store
        .bootstrap_admin_if_absent(NewAdminAccount {
            account_id: "admin-other".to_string(),
            login_name: "other-admin".to_string(),
            password_hash: Some("$argon2id$test".to_string()),
            display_name: None,
            email: None,
            avatar_url: None,
        })
        .await
        .unwrap();
    assert!(matches!(first, BootstrapOutcome::Created(_)));

    let root = store
        .bootstrap_admin_if_absent(NewAdminAccount {
            account_id: "admin-root".to_string(),
            login_name: "admin".to_string(),
            password_hash: Some("$argon2id$test".to_string()),
            display_name: None,
            email: None,
            avatar_url: None,
        })
        .await
        .unwrap();
    assert!(matches!(root, BootstrapOutcome::Created(_)));
    assert_eq!(store.active_admin_count().await.unwrap(), 2);
    assert_eq!(
        store
            .get_account_by_login("admin")
            .await
            .unwrap()
            .unwrap()
            .role,
        AccountRole::Admin
    );
}

#[tokio::test]
async fn managed_account_must_be_disabled_before_deletion() {
    let (_directory, store) = test_store().await;
    store
        .create_managed_user(managed_user(
            "delete-user",
            "delete-user",
            "delete-user",
            AccountRole::User,
            None,
        ))
        .await
        .unwrap();
    assert!(matches!(
        store.delete_managed_user("delete-user").await.unwrap_err(),
        UserRepositoryError::AccountMustBeDisabled(_)
    ));
    store
        .update_managed_user(
            "delete-user",
            ManagedUserUpdate {
                status: Some(AccountStatus::Disabled),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();
    store.delete_managed_user("delete-user").await.unwrap();
    assert!(
        store
            .get_account_by_id("delete-user")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn disabling_an_account_records_the_admin_snapshot_and_survives_deletion() {
    let (_directory, store) = test_store().await;
    create_admin(&store, "audit-admin").await;
    store
        .create_user_account(user_account("audit-target", "target-user"))
        .await
        .unwrap();

    store
        .update_managed_user(
            "audit-target",
            ManagedUserUpdate {
                status: Some(AccountStatus::Disabled),
                disabled_by: Some(AccountActor {
                    account_id: "audit-admin".to_string(),
                    login_name: "audit-admin".to_string(),
                }),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();
    store.delete_managed_user("audit-target").await.unwrap();

    let audit: (String, String, String, String) = sqlx::query_as(
        "SELECT target_account_id, target_login_name, admin_account_id, admin_login_name \
         FROM account_disable_audits",
    )
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(
        audit,
        (
            "audit-target".to_string(),
            "target-user".to_string(),
            "audit-admin".to_string(),
            "audit-admin".to_string(),
        )
    );
}

#[tokio::test]
async fn password_hash_update_is_atomic_and_increments_auth_version() {
    let (_directory, store) = test_store().await;
    let account = store
        .create_user_account(user_account("password-account", "password-user"))
        .await
        .unwrap();

    let updated = store
        .update_password_hash(
            &account.account_id,
            account.auth_version,
            "$argon2id$new-password-hash".to_string(),
        )
        .await
        .unwrap();
    assert_eq!(updated.auth_version, account.auth_version + 1);
    let record = store
        .get_login_record(&account.login_name)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.password_hash.as_deref(),
        Some("$argon2id$new-password-hash")
    );

    let error = store
        .update_password_hash(
            &account.account_id,
            account.auth_version,
            "$argon2id$stale-password-hash".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        UserRepositoryError::AccountVersionConflict {
            expected: 1,
            actual: 2,
            ..
        }
    ));
    assert_eq!(
        store
            .get_login_record(&account.login_name)
            .await
            .unwrap()
            .unwrap()
            .password_hash
            .as_deref(),
        Some("$argon2id$new-password-hash")
    );
}
