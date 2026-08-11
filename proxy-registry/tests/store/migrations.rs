use super::*;

#[tokio::test]
async fn migrates_v8_key_request_reviewer_names() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let store = SqliteUserRepository::connect(&path).await.unwrap();
    create_admin(&store, "admin-reviewer").await;
    store
        .create_user_account(user_account("account-reviewee", "reviewee"))
        .await
        .unwrap();
    store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "request-v8-review".to_string(),
            account_id: "account-reviewee".to_string(),
            request_message: None,
        })
        .await
        .unwrap();
    store
        .reject_key_generation_request(KeyRequestRejection {
            request_id: "request-v8-review".to_string(),
            reviewer_account_id: "admin-reviewer".to_string(),
            rejection_reason: Some("迁移测试拒绝原因".to_string()),
        })
        .await
        .unwrap();
    drop_v13_proxy_entry_columns(&store).await;
    drop_v12_registry_coordination_tables(&store).await;
    drop_v11_operation_audits(&store).await;
    drop_v10_account_disable_audits(&store).await;
    drop_v9_key_request_columns(&store).await;
    sqlx::query("PRAGMA user_version = 8")
        .execute(store.pool())
        .await
        .unwrap();
    store.pool().close().await;

    let reopened = SqliteUserRepository::connect(&path).await.unwrap();
    let request = reopened
        .get_key_generation_request("request-v8-review")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        request.reviewer_login_name.as_deref(),
        Some("admin-reviewer")
    );
    assert_eq!(request.rejection_reason, None);
}

#[tokio::test]
async fn disables_publicly_compromised_legacy_demo_keys_until_rotated() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let store = SqliteUserRepository::connect(&path).await.unwrap();
    create_admin(&store, "migration-admin").await;
    let created = store
        .create_user_record(NewUser::new(
            "compromised-demo",
            COMPROMISED_BUNDLED_DEMO_PUBLIC_KEYS[0],
            UserOrigin::Legacy,
        ))
        .await
        .unwrap();
    assert!(created.enabled);
    assert_eq!(created.key_version, 1);
    store.pool().close().await;

    let reopened = SqliteUserRepository::connect(&path).await.unwrap();
    let disabled = reopened
        .get_user("compromised-demo")
        .await
        .unwrap()
        .unwrap();
    assert!(!disabled.enabled);
    assert_eq!(disabled.key_version, 2);
    reopened.pool().close().await;

    // Repeated startups are idempotent. A real key rotation moves the profile away from the
    // denylisted public key and is the only supported way to enable it again.
    let reopened = SqliteUserRepository::connect(&path).await.unwrap();
    let unchanged = reopened
        .get_user("compromised-demo")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.key_version, 2);
    let rotated = reopened
        .update_user(
            "compromised-demo",
            UserUpdate {
                public_key_pem: Some(public_key()),
                enabled: Some(true),
                changed_by: Some(account_actor("migration-admin", "migration-admin")),
                audit_reason: Some("迁移后恢复代理连接".to_string()),
                ..UserUpdate::default()
            },
        )
        .await
        .unwrap();
    assert!(rotated.enabled);
    assert_eq!(rotated.key_version, 3);
    reopened.pool().close().await;

    let final_store = SqliteUserRepository::connect(&path).await.unwrap();
    assert!(
        final_store
            .get_user("compromised-demo")
            .await
            .unwrap()
            .unwrap()
            .enabled
    );
}

#[tokio::test]
async fn migrates_v4_database_to_agent_device_authorization_schema() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let store = SqliteUserRepository::connect(&path).await.unwrap();
    sqlx::query("ALTER TABLE key_generation_requests DROP COLUMN request_message")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TABLE agent_device_authorizations")
        .execute(store.pool())
        .await
        .unwrap();
    drop_v13_proxy_entry_columns(&store).await;
    drop_v12_registry_coordination_tables(&store).await;
    drop_v11_operation_audits(&store).await;
    drop_v8_proxy_address_tables(&store).await;
    drop_v10_account_disable_audits(&store).await;
    drop_v9_key_request_columns(&store).await;
    sqlx::query("PRAGMA user_version = 4")
        .execute(store.pool())
        .await
        .unwrap();
    store.pool().close().await;

    let reopened = SqliteUserRepository::connect(&path).await.unwrap();
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(version, SQLITE_SCHEMA_VERSION);
    let mut transaction = reopened.pool().begin().await.unwrap();
    let columns = table_columns(&mut transaction, "agent_device_authorizations")
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    assert!(columns.iter().any(|column| column == "device_code_hash"));
    assert!(
        columns
            .iter()
            .any(|column| column == "authorized_auth_version")
    );
    let mut transaction = reopened.pool().begin().await.unwrap();
    let key_request_columns = table_columns(&mut transaction, "key_generation_requests")
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    assert!(
        key_request_columns
            .iter()
            .any(|column| column == "request_message")
    );
}

#[tokio::test]
async fn migrates_v1_users_with_legacy_defaults() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE users (\
            username TEXT PRIMARY KEY COLLATE BINARY,\
            public_key_pem TEXT NOT NULL,\
            expires_at INTEGER,\
            created_at INTEGER NOT NULL,\
            updated_at INTEGER NOT NULL\
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("CREATE TABLE app_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO app_metadata (key, value) VALUES ('existing_key', 'value')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO users \
         (username, public_key_pem, expires_at, created_at, updated_at) VALUES (?, ?, NULL, 1, 1)",
    )
    .bind("alice")
    .bind(public_key())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("PRAGMA user_version = 1")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let store = SqliteUserRepository::connect(&path).await.unwrap();
    let user = store.get_user("alice").await.unwrap().unwrap();
    assert_eq!(user.origin, UserOrigin::Legacy);
    assert_eq!(user.permissions, default_proxy_permissions());
    assert!(user.enabled);
    assert_eq!(user.key_version, 1);
    let marker: String = sqlx::query_scalar("SELECT value FROM app_metadata WHERE key = ?")
        .bind("existing_key")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(marker, "value");
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(version, SQLITE_SCHEMA_VERSION);
}

#[tokio::test]
async fn migrates_v2_database_to_key_request_schema() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let store = SqliteUserRepository::connect(&path).await.unwrap();
    sqlx::query("DROP TABLE key_generation_requests")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TABLE user_access_records")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TABLE agent_device_authorizations")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM app_metadata WHERE key = ?")
        .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
        .execute(store.pool())
        .await
        .unwrap();
    drop_v13_proxy_entry_columns(&store).await;
    drop_v12_registry_coordination_tables(&store).await;
    drop_v10_account_disable_audits(&store).await;
    drop_v11_operation_audits(&store).await;
    drop_v8_proxy_address_tables(&store).await;
    sqlx::query("PRAGMA user_version = 2")
        .execute(store.pool())
        .await
        .unwrap();
    store.pool().close().await;

    let reopened = SqliteUserRepository::connect(&path).await.unwrap();
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(version, SQLITE_SCHEMA_VERSION);
    assert!(
        table_columns(
            &mut reopened.pool().begin().await.unwrap(),
            "key_generation_requests"
        )
        .await
        .unwrap()
        .iter()
        .any(|column| column == "approved_expires_at")
    );
    assert!(
        table_columns(
            &mut reopened.pool().begin().await.unwrap(),
            "key_generation_requests"
        )
        .await
        .unwrap()
        .iter()
        .any(|column| column == "request_message")
    );
    let mut transaction = reopened.pool().begin().await.unwrap();
    assert!(
        table_columns(&mut transaction, "user_access_records")
            .await
            .unwrap()
            .iter()
            .any(|column| column == "target_host")
    );
    transaction.rollback().await.unwrap();
    assert_eq!(
        reopened
            .get_access_log_settings()
            .await
            .unwrap()
            .retention_days,
        DEFAULT_ACCESS_LOG_RETENTION_DAYS
    );
}

mod legacy_access;

#[tokio::test]
async fn rejects_future_schema_version_without_downgrading() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::query("PRAGMA user_version = 15")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    assert!(matches!(
        SqliteUserRepository::connect(&path).await.unwrap_err(),
        UserRepositoryError::InvalidSchema(_)
    ));
    let options = SqliteConnectOptions::new().filename(&path);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 15);
}
