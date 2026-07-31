use super::*;

#[tokio::test]
async fn migrates_v3_duplicate_access_rows_into_address_counts() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let store = SqliteUserRepository::connect(&path).await.unwrap();
    store
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();
    sqlx::query("DROP TABLE user_access_records")
        .execute(&store.pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE agent_device_authorizations")
        .execute(&store.pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE key_generation_requests DROP COLUMN request_message")
        .execute(&store.pool)
        .await
        .unwrap();
    drop_v12_registry_coordination_tables(&store).await;
    drop_v10_account_disable_audits(&store).await;
    drop_v11_operation_audits(&store).await;
    drop_v9_key_request_columns(&store).await;
    sqlx::query(
        r#"
        CREATE TABLE user_access_records (
            record_id INTEGER NOT NULL PRIMARY KEY,
            username TEXT COLLATE BINARY NOT NULL,
            protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
            target_host TEXT NOT NULL,
            target_port INTEGER NOT NULL,
            accessed_at INTEGER NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
                ON UPDATE CASCADE ON DELETE CASCADE
        )
        "#,
    )
    .execute(&store.pool)
    .await
    .unwrap();
    for (protocol, host, port, accessed_at) in [
        ("tcp", "Example.COM", 443_i64, 100_i64),
        ("udp", "example.com", 8443_i64, 101_i64),
        ("tcp", "other.example", 80_i64, 99_i64),
    ] {
        sqlx::query(
            "INSERT INTO user_access_records \
             (username, protocol, target_host, target_port, accessed_at) \
             VALUES ('alice', ?, ?, ?, ?)",
        )
        .bind(protocol)
        .bind(host)
        .bind(port)
        .bind(accessed_at)
        .execute(&store.pool)
        .await
        .unwrap();
    }
    drop_v8_proxy_address_tables(&store).await;
    sqlx::query("PRAGMA user_version = 3")
        .execute(&store.pool)
        .await
        .unwrap();
    store.pool.close().await;

    let reopened = SqliteUserRepository::connect(&path).await.unwrap();
    let records = reopened.list_recent_access("alice", 0, 10).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].target_host, "example.com");
    assert_eq!(records[0].target_port, 8443);
    assert_eq!(records[0].protocol, AccessProtocol::Udp);
    assert_eq!(records[0].accessed_at, 101);
    assert_eq!(records[0].access_count, 2);
    assert_eq!(records[1].target_host, "other.example");
    assert_eq!(records[1].access_count, 1);

    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&reopened.pool)
        .await
        .unwrap();
    assert_eq!(version, SQLITE_SCHEMA_VERSION);
    let mut transaction = reopened.pool.begin().await.unwrap();
    assert!(
        table_columns(&mut transaction, "user_access_records")
            .await
            .unwrap()
            .iter()
            .any(|column| column == "access_count")
    );
    transaction.rollback().await.unwrap();
}
