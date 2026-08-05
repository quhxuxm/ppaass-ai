use super::*;

#[tokio::test]
async fn v8_migration_keeps_existing_profiles_but_does_not_guess_addresses() {
    let (directory, store) = test_store().await;
    store
        .create_managed_user(managed_user(
            "acc-migrated-address",
            "migrated-address",
            "migrated-address",
            AccountRole::User,
            None,
        ))
        .await
        .unwrap();
    drop_v12_registry_coordination_tables(&store).await;
    drop_v8_proxy_address_tables(&store).await;
    drop_v11_operation_audits(&store).await;
    drop_v10_account_disable_audits(&store).await;
    drop_v9_key_request_columns(&store).await;
    sqlx::query("PRAGMA user_version = 7")
        .execute(store.pool())
        .await
        .unwrap();
    store.pool().close().await;

    let reopened = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
        .await
        .unwrap();
    assert!(reopened.list_proxy_addresses().await.unwrap().is_empty());
    let migrated = reopened
        .get_managed_user("acc-migrated-address")
        .await
        .unwrap()
        .unwrap();
    assert!(migrated.profile.is_some());
    assert!(migrated.assigned_proxy_addresses.is_empty());
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(version, SQLITE_SCHEMA_VERSION);
}
