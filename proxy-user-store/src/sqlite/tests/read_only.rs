use super::*;

#[tokio::test]
async fn read_only_repository_observes_writer_changes_and_rejects_writes() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let writer = SqliteUserRepository::connect(&path).await.unwrap();
    writer
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();

    let reader = SqliteUserRepository::connect_read_only(&path)
        .await
        .unwrap();
    let query_only: i64 = sqlx::query_scalar("PRAGMA query_only")
        .fetch_one(&reader.pool)
        .await
        .unwrap();
    assert_eq!(query_only, 1);
    assert!(reader.get_user("alice").await.unwrap().is_some());
    writer
        .create_user("bob", &public_key(), None)
        .await
        .unwrap();
    assert!(reader.get_user("bob").await.unwrap().is_some());
    assert!(
        reader
            .create_user("mallory", &public_key(), None)
            .await
            .is_err()
    );
    assert!(writer.get_user("mallory").await.unwrap().is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn read_only_repository_opens_wal_database_without_os_write_bits() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let writer = SqliteUserRepository::connect(&path).await.unwrap();
    writer
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();
    for file in database_files(&path) {
        if file.try_exists().unwrap() {
            fs::set_permissions(&file, fs::Permissions::from_mode(0o440)).unwrap();
        }
    }

    let reader = SqliteUserRepository::connect_read_only(&path)
        .await
        .unwrap();
    assert!(reader.get_user("alice").await.unwrap().is_some());
    assert!(
        reader
            .create_user("mallory", &public_key(), None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn read_only_repository_requires_an_initialized_current_schema() {
    let directory = TempDir::new().unwrap();
    let missing = directory.path().join("missing.sqlite3");
    assert!(
        SqliteUserRepository::connect_read_only(&missing)
            .await
            .is_err()
    );

    let outdated = directory.path().join("outdated.sqlite3");
    let options = SqliteConnectOptions::new()
        .filename(&outdated)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::query("PRAGMA user_version = 4")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    assert!(matches!(
        SqliteUserRepository::connect_read_only(&outdated)
            .await
            .unwrap_err(),
        UserRepositoryError::InvalidSchema(_)
    ));
}
