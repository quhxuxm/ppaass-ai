use super::*;

#[tokio::test]
async fn creates_updates_and_persists_user() {
    let (directory, store) = test_store().await;
    create_admin(&store, "user-admin").await;
    let created = store
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();
    assert_eq!(created.permissions, default_proxy_permissions());
    assert!(created.enabled);
    assert_eq!(created.key_version, 1);

    let updated = store
        .update_user(
            "alice",
            UserUpdate {
                permissions: Some(vec![
                    "proxy.connect.udp".to_string(),
                    "proxy.connect.tcp".to_string(),
                    "proxy.connect.udp".to_string(),
                ]),
                expires_at: Some(Some(1_893_456_000)),
                changed_by: Some(account_actor("user-admin", "user-admin")),
                audit_reason: Some("更新用户权限".to_string()),
                ..UserUpdate::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.expires_at, Some(1_893_456_000));
    assert_eq!(updated.permissions, default_proxy_permissions());
    drop(store);

    let reopened = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
        .await
        .unwrap();
    assert_eq!(
        reopened
            .get_user("alice")
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        Some(1_893_456_000)
    );
}

#[tokio::test]
async fn public_key_update_invalidates_managed_private_key() {
    let (_directory, store) = test_store().await;
    store
        .create_managed_user(managed_user(
            "account-alice",
            "alice-login",
            "alice",
            AccountRole::User,
            None,
        ))
        .await
        .unwrap();
    let original = store.get_user("alice").await.unwrap().unwrap();
    let updated = store
        .update_user(
            "alice",
            UserUpdate {
                public_key_pem: Some(public_key()),
                ..UserUpdate::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.key_version, original.key_version + 1);
    assert!(
        store
            .load_encrypted_private_key("alice")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn preserves_legacy_database_profiles_without_web_accounts() {
    let (_directory, store) = test_store().await;
    let mut legacy = NewUser::new("alice", public_key(), UserOrigin::Legacy);
    legacy.expires_at = Some(1_893_456_000);
    store.create_user_record(legacy).await.unwrap();
    let user = store.get_user("alice").await.unwrap().unwrap();
    assert_eq!(user.origin, UserOrigin::Legacy);
    assert_eq!(user.permissions, default_proxy_permissions());
    assert!(user.enabled);
    assert_eq!(user.key_version, 1);
    assert_eq!(user.expires_at, Some(1_893_456_000));
    let managed = store
        .get_managed_user_by_username("alice")
        .await
        .unwrap()
        .unwrap();
    assert!(managed.account.is_none());
    assert!(!managed.has_private_key);
}

#[tokio::test]
async fn account_registration_rejects_login_reserved_by_legacy_database_profile() {
    let (_directory, store) = test_store().await;
    store
        .create_user_record(NewUser::new("alice", public_key(), UserOrigin::Legacy))
        .await
        .unwrap();

    let error = store
        .create_user_account(user_account("account-alice", "alice"))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        UserRepositoryError::Conflict(ref identifier) if identifier == "alice"
    ));
    assert!(store.get_account_by_login("alice").await.unwrap().is_none());
}

#[tokio::test]
async fn account_registration_rejects_login_reserved_by_direct_profile() {
    let (_directory, store) = test_store().await;
    store
        .create_user_record(NewUser::new("bob", public_key(), UserOrigin::Admin))
        .await
        .unwrap();

    let error = store
        .create_user_account(user_account("account-bob", "bob"))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        UserRepositoryError::Conflict(ref identifier) if identifier == "bob"
    ));
    assert!(store.get_account_by_login("bob").await.unwrap().is_none());
}

#[tokio::test]
async fn managed_registration_is_atomic_on_external_identity_conflict() {
    let (_directory, store) = test_store().await;
    let identity = ExternalIdentity {
        provider: "google".to_string(),
        subject: "subject-1".to_string(),
    };
    store
        .create_managed_user(managed_user(
            "account-alice",
            "alice-login",
            "alice",
            AccountRole::User,
            Some(identity.clone()),
        ))
        .await
        .unwrap();
    let error = store
        .create_managed_user(managed_user(
            "account-bob",
            "bob-login",
            "bob",
            AccountRole::User,
            Some(identity),
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        UserRepositoryError::ExternalIdentityConflict { .. }
    ));
    assert!(store.get_user("bob").await.unwrap().is_none());
    assert!(
        store
            .get_account_by_id("account-bob")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .load_encrypted_private_key("bob")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn account_only_registration_and_initial_approval_are_atomic() {
    let (_directory, store) = test_store().await;
    create_admin(&store, "admin-one").await;
    let mut account = user_account("account-alice", "alice-login");
    account.external_identity = Some(ExternalIdentity {
        provider: "google".to_string(),
        subject: "google-subject".to_string(),
    });
    let created = store.create_user_account(account).await.unwrap();
    assert_eq!(created.role, AccountRole::User);
    assert_eq!(created.status, AccountStatus::Active);
    assert!(created.linked_username.is_none());
    assert_eq!(
        store
            .get_account_by_external("google", "google-subject")
            .await
            .unwrap()
            .unwrap()
            .account_id,
        "account-alice"
    );

    let pending = store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "request-initial".to_string(),
            account_id: created.account_id.clone(),
            request_message: None,
        })
        .await
        .unwrap();
    assert_eq!(pending.kind, KeyRequestKind::Initial);
    assert_eq!(pending.status, KeyRequestStatus::Pending);
    assert_eq!(pending.expected_key_version, None);
    assert_eq!(
        store
            .get_key_generation_request("request-initial")
            .await
            .unwrap(),
        Some(pending.clone())
    );
    let conflict = store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "request-duplicate".to_string(),
            account_id: created.account_id.clone(),
            request_message: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        conflict,
        UserRepositoryError::PendingKeyRequestConflict {
            account_id,
            request_id
        } if account_id == "account-alice" && request_id == "request-initial"
    ));

    let expires_at = now() + 3600;
    let approved = store
        .approve_key_generation_request(initial_approval(
            "request-initial",
            "admin-one",
            "alice",
            expires_at,
        ))
        .await
        .unwrap();
    assert_eq!(approved.request.status, KeyRequestStatus::Approved);
    assert_eq!(approved.request.approved_expires_at, Some(expires_at));
    let profile = approved.managed_user.profile.unwrap();
    assert_eq!(profile.username, "alice");
    assert_eq!(profile.expires_at, Some(expires_at));
    assert!(approved.managed_user.has_private_key);
    assert_eq!(
        approved
            .managed_user
            .account
            .unwrap()
            .linked_username
            .as_deref(),
        Some("alice")
    );
    assert!(
        store
            .get_pending_key_generation_request("account-alice")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .load_encrypted_private_key("alice")
            .await
            .unwrap()
            .unwrap()
            .encrypted_private_key,
        b"encrypted-private-key"
    );
}
