use super::*;

#[tokio::test]
async fn active_admin_can_receive_initial_key_and_rotate_it_after_expiration() {
    let (_directory, store) = test_store().await;
    create_admin(&store, "admin-with-proxy").await;

    let initial = store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "admin-initial-request".to_string(),
            account_id: "admin-with-proxy".to_string(),
            request_message: None,
        })
        .await
        .unwrap();
    assert_eq!(initial.kind, KeyRequestKind::Initial);
    let first_expiration = now() + 3600;
    let approved = store
        .approve_key_generation_request(KeyRequestApproval {
            request_id: initial.request_id,
            reviewer_account_id: "admin-with-proxy".to_string(),
            expires_at: first_expiration,
            material: ApprovedKeyMaterial::Initial {
                profile: NewUser::new("admin-proxy-profile", public_key(), UserOrigin::Local),
                encrypted_private_key: b"admin-initial-envelope".to_vec(),
            },
        })
        .await
        .unwrap();
    assert_eq!(
        approved.managed_user.account.unwrap().role,
        AccountRole::Admin
    );
    assert_eq!(
        approved.managed_user.profile.as_ref().unwrap().expires_at,
        Some(first_expiration)
    );

    store
        .update_managed_user(
            "admin-with-proxy",
            ManagedUserUpdate {
                expires_at: Some(Some(now() - 1)),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();
    let rotation = store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "admin-rotation-request".to_string(),
            account_id: "admin-with-proxy".to_string(),
            request_message: None,
        })
        .await
        .unwrap();
    assert_eq!(rotation.kind, KeyRequestKind::Rotate);
    assert_eq!(rotation.expected_key_version, Some(1));

    let second_expiration = now() + 7200;
    let approved = store
        .approve_key_generation_request(KeyRequestApproval {
            request_id: rotation.request_id,
            reviewer_account_id: "admin-with-proxy".to_string(),
            expires_at: second_expiration,
            material: ApprovedKeyMaterial::Rotate {
                public_key_pem: public_key(),
                encrypted_private_key: b"admin-rotated-envelope".to_vec(),
            },
        })
        .await
        .unwrap();
    let profile = approved.managed_user.profile.unwrap();
    assert_eq!(profile.key_version, 2);
    assert_eq!(profile.expires_at, Some(second_expiration));
}
