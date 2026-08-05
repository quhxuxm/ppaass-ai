#[cfg(unix)]
use super::*;

#[cfg(unix)]
#[tokio::test]
async fn database_and_sidecar_files_are_owner_only_by_default() {
    use std::os::unix::fs::PermissionsExt;

    let (_directory, store) = test_store().await;
    store
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();

    for path in database_files(store.path()) {
        if path.try_exists().unwrap() {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn group_read_policy_never_grants_group_write() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let store = SqliteUserRepository::connect_with_permissions(
        &path,
        SqliteFilePermissions::OwnerReadWriteGroupRead,
    )
    .await
    .unwrap();
    store
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();
    store.apply_file_permissions().unwrap();

    for file in database_files(&path) {
        if file.try_exists().unwrap() {
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn group_writable_policy_applies_to_database_and_all_sidecars() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    fs::write(&path, []).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
    let store =
        SqliteUserRepository::connect_with_permissions(&path, SqliteFilePermissions::OwnerAndGroup)
            .await
            .unwrap();
    store
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();

    // WAL/SHM are created by SQLite from the main file's mode. A rollback
    // journal is uncommon after WAL is enabled, so create one to exercise
    // the same fd-based correction path for an existing file.
    let journal = database_sidecar_files(&path)[2].clone();
    fs::write(&journal, []).unwrap();
    for file in database_files(&path) {
        if file.try_exists().unwrap() {
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    store.apply_file_permissions().unwrap();

    for file in database_files(&path) {
        assert!(
            file.try_exists().unwrap(),
            "{} should exist",
            file.display()
        );
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o660
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn group_writable_policy_accepts_an_existing_database_with_the_target_mode() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    fs::write(&path, []).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();

    let store =
        SqliteUserRepository::connect_with_permissions(&path, SqliteFilePermissions::OwnerAndGroup)
            .await
            .unwrap();
    assert_eq!(
        fs::metadata(store.path()).unwrap().permissions().mode() & 0o777,
        0o660
    );
}

#[cfg(unix)]
#[tokio::test]
async fn sqlite_recreated_sidecars_inherit_the_group_writable_database_mode() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let store =
        SqliteUserRepository::connect_with_permissions(&path, SqliteFilePermissions::OwnerAndGroup)
            .await
            .unwrap();
    store.pool().close().await;
    let [wal, shm, _journal] = database_sidecar_files(&path);
    for sidecar in [&wal, &shm] {
        if sidecar.try_exists().unwrap() {
            fs::remove_file(sidecar).unwrap();
        }
    }

    // Open SQLite directly so no repository post-open chmod can mask the
    // mode SQLite gives to sidecars recreated later in the process lifetime.
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .min_connections(1)
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::query(
        "INSERT OR REPLACE INTO app_metadata (key, value) \
         VALUES ('sidecar-mode-test', 'written')",
    )
    .execute(&pool)
    .await
    .unwrap();

    for sidecar in [wal, shm] {
        assert!(sidecar.try_exists().unwrap());
        assert_eq!(
            fs::metadata(sidecar).unwrap().permissions().mode() & 0o777,
            0o660
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn refuses_a_symlink_database_without_changing_its_target() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = TempDir::new().unwrap();
    let target = directory.path().join("target");
    let database = directory.path().join("users.sqlite3");
    fs::write(&target, b"must-not-be-opened-as-sqlite").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
    symlink(&target, &database).unwrap();

    assert!(matches!(
        SqliteUserRepository::connect_with_permissions(
            &database,
            SqliteFilePermissions::OwnerAndGroup,
        )
        .await
        .unwrap_err(),
        UserRepositoryError::Io(_)
    ));
    assert_eq!(
        fs::metadata(target).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[cfg(unix)]
#[tokio::test]
async fn refuses_a_symlink_sidecar_without_changing_its_target() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = TempDir::new().unwrap();
    let database = directory.path().join("users.sqlite3");
    let target = directory.path().join("target");
    fs::write(&database, []).unwrap();
    fs::write(&target, b"must-not-be-opened-as-a-journal").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
    let journal = database_sidecar_files(&database)[2].clone();
    symlink(&target, journal).unwrap();

    assert!(matches!(
        SqliteUserRepository::connect(&database).await.unwrap_err(),
        UserRepositoryError::Io(_)
    ));
    assert_eq!(
        fs::metadata(target).unwrap().permissions().mode() & 0o777,
        0o640
    );
}
