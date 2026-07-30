use super::*;

#[test]
fn proxy_addresses_are_canonical_and_strictly_validated() {
    assert_eq!(
        normalize_proxy_address("EXAMPLE.com:080").unwrap(),
        "example.com:80"
    );
    assert_eq!(
        normalize_proxy_address("127.0.0.1:8080").unwrap(),
        "127.0.0.1:8080"
    );
    assert_eq!(
        normalize_proxy_address("[2001:db8::1]:443").unwrap(),
        "[2001:db8::1]:443"
    );
    for invalid in [
        "https://example.com:443",
        "example.com/path:443",
        "example.com :443",
        "example.com:0",
        "-example.com:443",
        "example..com:443",
        "2001:db8::1:443",
    ] {
        assert!(
            matches!(
                normalize_proxy_address(invalid),
                Err(ValidationError::InvalidProxyAddress)
            ),
            "{invalid}"
        );
    }
    assert!(matches!(
        normalize_proxy_address_ids(&["pxy_one".to_string(), "pxy_one".to_string()]),
        Err(ValidationError::DuplicateProxyAddressId)
    ));
}

#[tokio::test]
async fn assigned_addresses_are_atomic_unique_and_cannot_be_disabled() {
    let (_directory, store) = test_store().await;
    create_admin(&store, "address-admin").await;
    store
        .create_proxy_address(NewProxyAddress {
            proxy_address_id: "pxy_backup".to_string(),
            label: "Backup".to_string(),
            address: "EXAMPLE.com:080".to_string(),
            enabled: true,
        })
        .await
        .unwrap();
    assert!(matches!(
        store
            .create_proxy_address(NewProxyAddress {
                proxy_address_id: "pxy_duplicate".to_string(),
                label: "Duplicate".to_string(),
                address: "example.com:80".to_string(),
                enabled: true,
            })
            .await
            .unwrap_err(),
        UserRepositoryError::ProxyAddressConflict(_)
    ));

    let created = store
        .create_managed_user(managed_user(
            "acc-address-user",
            "address-user",
            "address-user",
            AccountRole::User,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(
        created.assigned_proxy_addresses[0].proxy_address_id,
        TEST_PROXY_ADDRESS_ID
    );
    assert!(matches!(
        store
            .update_proxy_address(
                TEST_PROXY_ADDRESS_ID,
                ProxyAddressUpdate {
                    enabled: Some(false),
                    changed_by: Some(account_actor("address-admin", "address-admin")),
                    audit_reason: Some("测试已分配节点不能停用".to_string()),
                    ..ProxyAddressUpdate::default()
                },
            )
            .await
            .unwrap_err(),
        UserRepositoryError::ProxyAddressInUse(_)
    ));

    let updated = store
        .update_managed_user(
            "acc-address-user",
            ManagedUserUpdate {
                proxy_address_ids: Some(vec!["pxy_backup".to_string()]),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        updated.assigned_proxy_addresses[0].address,
        "example.com:80"
    );
    store
        .update_proxy_address(
            TEST_PROXY_ADDRESS_ID,
            ProxyAddressUpdate {
                enabled: Some(false),
                changed_by: Some(account_actor("address-admin", "address-admin")),
                audit_reason: Some("停用未分配节点".to_string()),
                ..ProxyAddressUpdate::default()
            },
        )
        .await
        .unwrap();
    store
        .delete_proxy_address(TEST_PROXY_ADDRESS_ID)
        .await
        .unwrap();

    for invalid in [
        Vec::new(),
        vec!["pxy_backup".to_string(), "pxy_backup".to_string()],
    ] {
        assert!(matches!(
            store
                .update_managed_user(
                    "acc-address-user",
                    ManagedUserUpdate {
                        proxy_address_ids: Some(invalid),
                        ..ManagedUserUpdate::default()
                    },
                )
                .await
                .unwrap_err(),
            UserRepositoryError::Validation(_)
        ));
    }
    let unchanged = store
        .get_managed_user("acc-address-user")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.assigned_proxy_addresses.len(), 1);
}
