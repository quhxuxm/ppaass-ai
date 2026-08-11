use super::*;

#[tokio::test]
async fn v15_migration_keeps_only_assigned_selection_and_enables_multi_select() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let store = SqliteUserRepository::connect(&path).await.unwrap();
    store
        .create_proxy_address(NewProxyAddress {
            proxy_address_id: TEST_PROXY_ADDRESS_ID.to_string(),
            label: "Primary".to_string(),
            address: "primary.example:443".to_string(),
            enabled: true,
        })
        .await
        .unwrap();
    store
        .create_proxy_address(NewProxyAddress {
            proxy_address_id: "pxy_backup".to_string(),
            label: "Backup".to_string(),
            address: "backup.example:443".to_string(),
            enabled: true,
        })
        .await
        .unwrap();
    for (account_id, login_name) in [
        ("acc-migration-assigned", "migration-assigned"),
        ("acc-migration-unassigned", "migration-unassigned"),
    ] {
        store
            .create_managed_user(managed_user(
                account_id,
                login_name,
                login_name,
                AccountRole::Admin,
                None,
            ))
            .await
            .unwrap();
    }
    store
        .update_managed_user(
            "acc-migration-assigned",
            ManagedUserUpdate {
                proxy_address_ids: Some(vec![
                    TEST_PROXY_ADDRESS_ID.to_string(),
                    "pxy_backup".to_string(),
                ]),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();

    sqlx::query("DROP INDEX idx_account_proxy_entry_selections_address")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TABLE account_proxy_entry_selections")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE account_proxy_entry_selections (\
            account_id TEXT COLLATE BINARY NOT NULL PRIMARY KEY,\
            proxy_address_id TEXT COLLATE BINARY NOT NULL,\
            selected_at INTEGER NOT NULL,\
            FOREIGN KEY(account_id) REFERENCES web_accounts(account_id) ON DELETE CASCADE,\
            FOREIGN KEY(proxy_address_id) REFERENCES proxy_addresses(proxy_address_id) ON DELETE CASCADE\
        )",
    )
    .execute(store.pool())
    .await
    .unwrap();
    for account_id in ["acc-migration-assigned", "acc-migration-unassigned"] {
        sqlx::query(
            "INSERT INTO account_proxy_entry_selections \
             (account_id, proxy_address_id, selected_at) VALUES (?, 'pxy_backup', 100)",
        )
        .bind(account_id)
        .execute(store.pool())
        .await
        .unwrap();
    }
    sqlx::query("PRAGMA user_version = 14")
        .execute(store.pool())
        .await
        .unwrap();
    store.pool().close().await;

    let reopened = SqliteUserRepository::connect(&path).await.unwrap();
    let assigned = reopened
        .get_managed_user("acc-migration-assigned")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(assigned.selected_proxy_addresses.len(), 1);
    let unassigned = reopened
        .get_managed_user("acc-migration-unassigned")
        .await
        .unwrap()
        .unwrap();
    assert!(unassigned.selected_proxy_addresses.is_empty());

    let selected = reopened
        .select_proxy_addresses(
            "acc-migration-assigned",
            &[TEST_PROXY_ADDRESS_ID.to_string(), "pxy_backup".to_string()],
            "agent.proxy_entry.select",
        )
        .await
        .unwrap();
    assert_eq!(selected.selected_proxy_addresses.len(), 2);
}
