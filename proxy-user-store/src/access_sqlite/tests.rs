use super::*;
use crate::{SqliteUserRepository, UserRepository};
use protocol::RsaKeyPair;
use tempfile::TempDir;

fn record(username: &str, host: &str, accessed_at: i64) -> NewAccessRecord {
    NewAccessRecord {
        username: username.to_string(),
        protocol: AccessProtocol::Tcp,
        target_host: host.to_string(),
        target_port: 443,
        accessed_at,
    }
}

fn public_key() -> String {
    RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap()
}

#[test]
fn access_pool_keeps_one_connection_for_the_process_lifetime() {
    let options = connection::access_pool_options();
    assert_eq!(options.get_min_connections(), 1);
    assert_eq!(options.get_max_connections(), 1);
    assert_eq!(options.get_idle_timeout(), None);
    assert_eq!(options.get_max_lifetime(), None);
}

#[cfg(unix)]
#[tokio::test]
async fn separate_repositories_keep_sidecars_and_writes_visible_across_reopen() {
    use std::os::unix::fs::MetadataExt;

    let directory = TempDir::new().unwrap();
    let path = directory.path().join("access.sqlite3");
    let proxy_store = SqliteAccessLogRepository::connect(&path).await.unwrap();
    let web_store = SqliteAccessLogRepository::connect(&path).await.unwrap();
    proxy_store
        .record_access(record("alice", "shared.example", 100))
        .await
        .unwrap();
    assert_eq!(
        web_store.list_recent_access("alice", 0, 10).await.unwrap()[0].access_count,
        1
    );

    let [wal_path, shm_path, _journal_path] = database_sidecar_files(&path);
    let sidecar_identity = |sidecar: &Path| {
        let metadata = fs::metadata(sidecar).unwrap();
        (metadata.dev(), metadata.ino())
    };
    let initial_wal = sidecar_identity(&wal_path);
    let initial_shm = sidecar_identity(&shm_path);

    web_store.pool.close().await;
    proxy_store
        .record_access(record("alice", "shared.example", 101))
        .await
        .unwrap();
    assert_eq!(sidecar_identity(&wal_path), initial_wal);
    assert_eq!(sidecar_identity(&shm_path), initial_shm);

    let reopened_web_store = SqliteAccessLogRepository::connect(&path).await.unwrap();
    let records = reopened_web_store
        .list_recent_access("alice", 0, 10)
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].access_count, 2);
    assert_eq!(records[0].accessed_at, 101);
    assert_eq!(sidecar_identity(&wal_path), initial_wal);
    assert_eq!(sidecar_identity(&shm_path), initial_shm);
}

#[tokio::test]
async fn access_database_does_not_require_a_user_row() {
    let directory = TempDir::new().unwrap();
    let store = SqliteAccessLogRepository::connect(directory.path().join("access.sqlite3"))
        .await
        .unwrap();
    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
            .fetch_all(&store.pool)
            .await
            .unwrap();
    assert_eq!(
        tables,
        vec![
            "app_metadata".to_string(),
            "user_access_records".to_string()
        ]
    );
    store
        .record_access(record("alice", "Example.COM", 100))
        .await
        .unwrap();
    store
        .record_access(record("alice", "example.com", 101))
        .await
        .unwrap();
    let records = store.list_recent_access("alice", 0, 10).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].access_count, 2);
    assert_eq!(records[0].accessed_at, 101);
}

#[tokio::test]
async fn imports_legacy_records_and_retention_idempotently() {
    let directory = TempDir::new().unwrap();
    let user_path = directory.path().join("users.sqlite3");
    let user_store = SqliteUserRepository::connect(&user_path).await.unwrap();
    user_store
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();
    user_store
        .record_access(record("alice", "legacy.example", 100))
        .await
        .unwrap();
    user_store
        .record_access(record("alice", "legacy.example", 101))
        .await
        .unwrap();
    user_store.set_access_log_retention_days(30).await.unwrap();

    let access_store = SqliteAccessLogRepository::connect(directory.path().join("access.sqlite3"))
        .await
        .unwrap();
    access_store
        .record_access(record("alice", "new.example", 102))
        .await
        .unwrap();
    assert_eq!(
        access_store
            .import_legacy_user_database_once(&user_path)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        access_store
            .import_legacy_user_database_once(&user_path)
            .await
            .unwrap(),
        0
    );
    // Simulate a previous process already applying retention to an expired migrated row.
    assert_eq!(
        access_store.purge_access_records_before(102).await.unwrap(),
        1
    );
    assert_eq!(
        access_store
            .cleanup_legacy_user_database_access_records(&user_path, 102)
            .await
            .unwrap(),
        1
    );
    let checkpoint_marker: Option<String> =
        sqlx::query_scalar("SELECT value FROM app_metadata WHERE key = ?")
            .bind(LEGACY_USER_DATABASE_CHECKPOINT_KEY)
            .fetch_optional(&access_store.pool)
            .await
            .unwrap();
    assert_eq!(checkpoint_marker.as_deref(), Some("completed"));

    // A normal Web restart can overlap a live Proxy reader. After the one-time checkpoint is
    // marked complete, cleanup must not checkpoint again and fail availability.
    let read_pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&user_path)
                .read_only(true),
        )
        .await
        .unwrap();
    let mut read_transaction = read_pool.begin().await.unwrap();
    let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *read_transaction)
        .await
        .unwrap();
    user_store
        .create_user("bob", &public_key(), None)
        .await
        .unwrap();
    assert_eq!(
        access_store
            .cleanup_legacy_user_database_access_records(&user_path, 102)
            .await
            .unwrap(),
        0
    );
    read_transaction.rollback().await.unwrap();
    read_pool.close().await;
    assert!(
        user_store
            .list_recent_access("alice", 0, 10)
            .await
            .unwrap()
            .is_empty()
    );
    let records = access_store
        .list_recent_access("alice", 0, 10)
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target_host, "new.example");
    assert_eq!(
        access_store.get_access_log_settings().await.unwrap(),
        AccessLogSettings { retention_days: 30 }
    );
}

#[tokio::test]
async fn cleanup_refuses_to_delete_unverified_retained_source_rows() {
    let directory = TempDir::new().unwrap();
    let user_path = directory.path().join("users.sqlite3");
    let user_store = SqliteUserRepository::connect(&user_path).await.unwrap();
    user_store
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();
    user_store
        .record_access(record("alice", "must-retain.example", 100))
        .await
        .unwrap();

    let access_store = SqliteAccessLogRepository::connect(directory.path().join("access.sqlite3"))
        .await
        .unwrap();
    access_store
        .import_legacy_user_database_once(&user_path)
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_access_records WHERE target_host = ?")
        .bind("must-retain.example")
        .execute(&access_store.pool)
        .await
        .unwrap();

    assert!(
        access_store
            .cleanup_legacy_user_database_access_records(&user_path, 0)
            .await
            .is_err()
    );
    assert_eq!(
        user_store
            .list_recent_access("alice", 0, 10)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn busy_access_checkpoint_is_reported_and_can_be_retried() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("access.sqlite3");
    let store = SqliteAccessLogRepository::connect(&path).await.unwrap();
    store
        .record_access(record("alice", "first.example", 100))
        .await
        .unwrap();

    let read_pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path).read_only(true))
        .await
        .unwrap();
    let mut read_transaction = read_pool.begin().await.unwrap();
    let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_access_records")
        .fetch_one(&mut *read_transaction)
        .await
        .unwrap();
    store
        .record_access(record("alice", "second.example", 101))
        .await
        .unwrap();

    assert!(store.checkpoint_wal().await.is_err());
    read_transaction.rollback().await.unwrap();
    read_pool.close().await;
    store.checkpoint_wal().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn access_database_group_write_mode_applies_to_main_and_sidecars() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TempDir::new().unwrap();
    let path = directory.path().join("access.sqlite3");
    let store = SqliteAccessLogRepository::connect_with_permissions(
        &path,
        SqliteFilePermissions::OwnerAndGroup,
    )
    .await
    .unwrap();
    store.pool.close().await;
    let [wal, shm, _journal] = database_sidecar_files(&path);
    for sidecar in [&wal, &shm] {
        if sidecar.try_exists().unwrap() {
            fs::remove_file(sidecar).unwrap();
        }
    }

    // Reopen SQLite directly so repository post-open chmod cannot mask the mode inherited
    // by sidecars created later in either service's process lifetime.
    let pool = SqlitePoolOptions::new()
        .min_connections(1)
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .journal_mode(SqliteJournalMode::Wal),
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT OR REPLACE INTO app_metadata (key, value) \
         VALUES ('access-sidecar-mode-test', 'written')",
    )
    .execute(&pool)
    .await
    .unwrap();

    for file in [path, wal, shm] {
        assert!(file.try_exists().unwrap());
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o660
        );
    }
}

#[tokio::test]
async fn rejects_using_the_user_database_as_the_access_database() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let _user_store = SqliteUserRepository::connect(&path).await.unwrap();
    // Opening the user DB as an access DB fails schema validation before import.
    assert!(SqliteAccessLogRepository::connect(&path).await.is_err());
}

#[cfg(unix)]
#[test]
fn rejects_a_hard_link_before_any_permission_change() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TempDir::new().unwrap();
    let user_path = directory.path().join("users.sqlite3");
    let access_path = directory.path().join("access.sqlite3");
    fs::write(&user_path, b"user-database-placeholder").unwrap();
    fs::set_permissions(&user_path, fs::Permissions::from_mode(0o640)).unwrap();
    fs::hard_link(&user_path, &access_path).unwrap();

    assert!(
        SqliteAccessLogRepository::validate_distinct_database_paths(&access_path, &user_path)
            .is_err()
    );
    assert_eq!(
        fs::metadata(&user_path).unwrap().permissions().mode() & 0o777,
        0o640
    );
}
