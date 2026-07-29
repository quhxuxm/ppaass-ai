use super::*;

#[tokio::test]
async fn user_account_capacity_is_atomic_and_a_deleted_account_frees_a_slot() {
    let (_directory, mut store) = test_store().await;
    store.max_user_accounts = 1;
    let first_store = store.clone();
    let second_store = store.clone();
    let (first, second) = tokio::join!(
        first_store.create_user_account(user_account("account-alice", "alice-login")),
        second_store.create_user_account(user_account("account-bob", "bob-login")),
    );
    assert_eq!(
        usize::from(first.is_ok()) + usize::from(second.is_ok()),
        1,
        "BEGIN IMMEDIATE 下的容量检查与插入必须是原子的"
    );
    let capacity_error = first.err().or_else(|| second.err()).unwrap();
    assert!(matches!(
        capacity_error,
        UserRepositoryError::UserAccountCapacity
    ));

    let created_id = store
        .list_managed_users()
        .await
        .unwrap()
        .into_iter()
        .find_map(|managed| managed.account.map(|account| account.account_id))
        .unwrap();
    store
        .update_managed_user(
            &created_id,
            ManagedUserUpdate {
                status: Some(AccountStatus::Disabled),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();
    store.delete_managed_user(&created_id).await.unwrap();
    store
        .create_user_account(user_account("account-carol", "carol-login"))
        .await
        .unwrap();
}

#[tokio::test]
async fn failed_initial_approval_rolls_back_and_request_remains_pending() {
    let (_directory, store) = test_store().await;
    create_admin(&store, "admin-one").await;
    store
        .create_user_account(user_account("account-alice", "alice-login"))
        .await
        .unwrap();
    store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "request-initial".to_string(),
            account_id: "account-alice".to_string(),
            request_message: None,
        })
        .await
        .unwrap();

    let error = store
        .approve_key_generation_request(KeyRequestApproval {
            request_id: "request-initial".to_string(),
            reviewer_account_id: "admin-one".to_string(),
            expires_at: now() + 3600,
            material: ApprovedKeyMaterial::Rotate {
                public_key_pem: public_key(),
                encrypted_private_key: b"wrong-kind-envelope".to_vec(),
            },
        })
        .await
        .unwrap_err();
    assert!(matches!(error, UserRepositoryError::StaleKeyRequest { .. }));
    assert!(store.get_user("alice").await.unwrap().is_none());
    assert!(
        store
            .get_account_by_id("account-alice")
            .await
            .unwrap()
            .unwrap()
            .linked_username
            .is_none()
    );
    assert_eq!(
        store
            .get_pending_key_generation_request("account-alice")
            .await
            .unwrap()
            .unwrap()
            .status,
        KeyRequestStatus::Pending
    );

    let past_expiration = now() - 1;
    let error = store
        .approve_key_generation_request(initial_approval(
            "request-initial",
            "admin-one",
            "alice",
            past_expiration,
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        UserRepositoryError::InvalidApprovalExpiration { .. }
    ));
    assert!(store.get_user("alice").await.unwrap().is_none());
}
