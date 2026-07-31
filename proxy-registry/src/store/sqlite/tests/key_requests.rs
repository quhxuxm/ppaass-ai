use super::*;

#[tokio::test]
async fn rejects_then_allows_a_new_request() {
    let (_directory, store) = test_store().await;
    create_admin(&store, "admin-one").await;
    store
        .create_user_account(user_account("account-alice", "alice-login"))
        .await
        .unwrap();
    store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "request-one".to_string(),
            account_id: "account-alice".to_string(),
            request_message: Some("  请尽快审批，谢谢  ".to_string()),
        })
        .await
        .unwrap();
    let rejected = store
        .reject_key_generation_request(KeyRequestRejection {
            request_id: "request-one".to_string(),
            reviewer_account_id: "admin-one".to_string(),
            rejection_reason: Some("  当前用途说明不完整，请补充后重试。  ".to_string()),
        })
        .await
        .unwrap();
    assert_eq!(rejected.status, KeyRequestStatus::Rejected);
    assert_eq!(
        rejected.request_message.as_deref(),
        Some("请尽快审批，谢谢")
    );
    assert_eq!(rejected.reviewer_account_id.as_deref(), Some("admin-one"));
    assert_eq!(rejected.reviewer_login_name.as_deref(), Some("admin-one"));
    assert_eq!(
        rejected.rejection_reason.as_deref(),
        Some("当前用途说明不完整，请补充后重试。")
    );
    assert!(rejected.reviewed_at.is_some());
    assert_eq!(rejected.approved_expires_at, None);
    assert_eq!(
        store
            .get_latest_key_generation_request("account-alice")
            .await
            .unwrap(),
        Some(rejected)
    );

    let next = store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "request-two".to_string(),
            account_id: "account-alice".to_string(),
            request_message: None,
        })
        .await
        .unwrap();
    assert_eq!(next.kind, KeyRequestKind::Initial);
    assert_eq!(
        store.list_pending_key_generation_requests().await.unwrap(),
        vec![next]
    );
}

#[tokio::test]
async fn expired_key_can_request_and_receive_atomic_rotation() {
    let (_directory, store) = test_store().await;
    create_admin(&store, "admin-one").await;
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
    store
        .update_managed_user(
            "account-alice",
            ManagedUserUpdate {
                expires_at: Some(Some(now() - 1)),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();
    let request = store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "request-rotate".to_string(),
            account_id: "account-alice".to_string(),
            request_message: None,
        })
        .await
        .unwrap();
    assert_eq!(request.kind, KeyRequestKind::Rotate);
    assert_eq!(request.expected_key_version, Some(original.key_version));

    let new_public_key = public_key();
    let expires_at = now() + 7200;
    let approved = store
        .approve_key_generation_request(KeyRequestApproval {
            request_id: request.request_id,
            reviewer_account_id: "admin-one".to_string(),
            expires_at,
            proxy_address_ids: vec![TEST_PROXY_ADDRESS_ID.to_string()],
            material: ApprovedKeyMaterial::Rotate {
                public_key_pem: new_public_key.clone(),
                encrypted_private_key: b"rotated-envelope".to_vec(),
            },
            audit_reason: "批准密钥轮换".to_string(),
        })
        .await
        .unwrap();
    let profile = approved.managed_user.profile.unwrap();
    assert_eq!(
        profile.public_key_pem,
        normalize_public_key_pem(&new_public_key).unwrap()
    );
    assert_eq!(profile.key_version, original.key_version + 1);
    assert_eq!(profile.expires_at, Some(expires_at));
    let private = store
        .load_encrypted_private_key("alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(private.key_version, profile.key_version);
    assert_eq!(private.encrypted_private_key, b"rotated-envelope");
}

#[tokio::test]
async fn active_key_is_ineligible_but_missing_envelope_can_be_recovered() {
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
    let error = store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "request-active".to_string(),
            account_id: "account-alice".to_string(),
            request_message: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        UserRepositoryError::KeyRequestNotEligible { .. }
    ));

    sqlx::query("DELETE FROM user_private_keys WHERE username = 'alice'")
        .execute(&store.pool)
        .await
        .unwrap();
    let recovery = store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "request-recovery".to_string(),
            account_id: "account-alice".to_string(),
            request_message: None,
        })
        .await
        .unwrap();
    assert_eq!(recovery.kind, KeyRequestKind::Rotate);
    assert_eq!(recovery.expected_key_version, Some(1));
}

#[tokio::test]
async fn rotation_approval_rechecks_disabled_profile_inside_transaction() {
    let (_directory, store) = test_store().await;
    create_admin(&store, "admin-one").await;
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
    store
        .update_managed_user(
            "account-alice",
            ManagedUserUpdate {
                expires_at: Some(Some(now() - 1)),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();
    let original = store.get_user("alice").await.unwrap().unwrap();
    let original_private = store
        .load_encrypted_private_key("alice")
        .await
        .unwrap()
        .unwrap();
    store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "request-disabled".to_string(),
            account_id: "account-alice".to_string(),
            request_message: None,
        })
        .await
        .unwrap();
    store
        .update_managed_user(
            "account-alice",
            ManagedUserUpdate {
                enabled: Some(false),
                changed_by: Some(account_actor("admin-one", "admin-one")),
                audit_reason: Some("验证停用用户不能审批".to_string()),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();

    let error = store
        .approve_key_generation_request(KeyRequestApproval {
            request_id: "request-disabled".to_string(),
            reviewer_account_id: "admin-one".to_string(),
            expires_at: now() + 3600,
            proxy_address_ids: vec![TEST_PROXY_ADDRESS_ID.to_string()],
            material: ApprovedKeyMaterial::Rotate {
                public_key_pem: public_key(),
                encrypted_private_key: b"must-not-commit".to_vec(),
            },
            audit_reason: "测试停用用户审批".to_string(),
        })
        .await
        .unwrap_err();
    assert!(matches!(error, UserRepositoryError::StaleKeyRequest { .. }));
    let after = store.get_user("alice").await.unwrap().unwrap();
    assert!(!after.enabled);
    assert_eq!(after.public_key_pem, original.public_key_pem);
    assert_eq!(after.key_version, original.key_version);
    assert_eq!(after.expires_at, original.expires_at);
    assert_eq!(
        store
            .load_encrypted_private_key("alice")
            .await
            .unwrap()
            .unwrap()
            .encrypted_private_key,
        original_private.encrypted_private_key
    );
    assert_eq!(
        store
            .get_key_generation_request("request-disabled")
            .await
            .unwrap()
            .unwrap()
            .status,
        KeyRequestStatus::Pending
    );
}

#[tokio::test]
async fn concurrent_approval_only_commits_one_keypair() {
    let (_directory, store) = test_store().await;
    create_admin(&store, "admin-one").await;
    store
        .create_user_account(user_account("account-alice", "alice-login"))
        .await
        .unwrap();
    store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "request-race".to_string(),
            account_id: "account-alice".to_string(),
            request_message: None,
        })
        .await
        .unwrap();
    let first_public = public_key();
    let second_public = public_key();
    let expires_at = now() + 3600;
    let first_store = store.clone();
    // 使用独立连接池模拟两个 Proxy Registry 进程，而不是只在同一个池内并发。
    let second_store = SqliteUserRepository::connect(&store.path).await.unwrap();
    let first = tokio::spawn(async move {
        first_store
            .approve_key_generation_request(KeyRequestApproval {
                request_id: "request-race".to_string(),
                reviewer_account_id: "admin-one".to_string(),
                expires_at,
                proxy_address_ids: vec![TEST_PROXY_ADDRESS_ID.to_string()],
                material: ApprovedKeyMaterial::Initial {
                    profile: NewUser::new("alice", first_public, UserOrigin::Local),
                    encrypted_private_key: b"first-envelope".to_vec(),
                },
                audit_reason: "并发审批一".to_string(),
            })
            .await
    });
    let second = tokio::spawn(async move {
        second_store
            .approve_key_generation_request(KeyRequestApproval {
                request_id: "request-race".to_string(),
                reviewer_account_id: "admin-one".to_string(),
                expires_at,
                proxy_address_ids: vec![TEST_PROXY_ADDRESS_ID.to_string()],
                material: ApprovedKeyMaterial::Initial {
                    profile: NewUser::new("alice", second_public, UserOrigin::Local),
                    encrypted_private_key: b"second-envelope".to_vec(),
                },
                audit_reason: "并发审批二".to_string(),
            })
            .await
    });
    let (first, second) = tokio::join!(first, second);
    let results = [first.unwrap(), second.unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(UserRepositoryError::KeyRequestAlreadyReviewed { .. })
            ))
            .count(),
        1
    );
    let request = store
        .get_key_generation_request("request-race")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.status, KeyRequestStatus::Approved);
    assert_eq!(store.list_users().await.unwrap().len(), 1);
    let private = store
        .load_encrypted_private_key("alice")
        .await
        .unwrap()
        .unwrap();
    assert!(
        private.encrypted_private_key == b"first-envelope"
            || private.encrypted_private_key == b"second-envelope"
    );
}
