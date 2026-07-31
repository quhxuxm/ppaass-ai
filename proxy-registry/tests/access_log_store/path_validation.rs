use super::*;

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
