mod support;

use proxy_entry::{config::ProxyConfig, control_plane::RemoteControlPlane, error::ProxyError};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn config_in(directory: &tempfile::TempDir) -> ProxyConfig {
    let token_path = directory.path().join("control-token");
    std::fs::write(&token_path, TEST_TOKEN).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = support::proxy_config("");
    config.registry_url = "http://127.0.0.1:9".to_string();
    config.registry_control_token_path = token_path.display().to_string();
    config.authorization_database_path = directory
        .path()
        .join("authorization.sqlite3")
        .display()
        .to_string();
    config
}

#[tokio::test]
async fn corrupted_existing_database_fails_startup_without_reinitializing() {
    let directory = tempfile::TempDir::new().unwrap();
    let config = config_in(&directory);
    std::fs::write(
        &config.authorization_database_path,
        b"not a sqlite database",
    )
    .unwrap();

    let result = RemoteControlPlane::new(&config).await;
    assert!(matches!(result, Err(ProxyError::Configuration(_))));
    assert_eq!(
        std::fs::read(&config.authorization_database_path).unwrap(),
        b"not a sqlite database"
    );
}

#[tokio::test]
async fn zero_length_database_left_before_initialization_is_safely_initialized() {
    let directory = tempfile::TempDir::new().unwrap();
    let config = config_in(&directory);
    std::fs::write(&config.authorization_database_path, []).unwrap();

    RemoteControlPlane::new(&config).await.unwrap();
    assert!(
        std::fs::metadata(&config.authorization_database_path)
            .unwrap()
            .len()
            > 0
    );
}

#[tokio::test]
async fn newer_database_schema_fails_startup_without_mutation() {
    let directory = tempfile::TempDir::new().unwrap();
    let config = config_in(&directory);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&config.authorization_database_path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE authorization_schema_version (\
         singleton INTEGER PRIMARY KEY, version INTEGER NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO authorization_schema_version (singleton, version) VALUES (1, 2)")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let result = RemoteControlPlane::new(&config).await;
    assert!(matches!(result, Err(ProxyError::Configuration(_))));
}

#[cfg(unix)]
#[tokio::test]
async fn symbolic_link_database_is_rejected() {
    let directory = tempfile::TempDir::new().unwrap();
    let config = config_in(&directory);
    let target = directory.path().join("target.sqlite3");
    std::fs::write(&target, []).unwrap();
    std::os::unix::fs::symlink(&target, &config.authorization_database_path).unwrap();

    let result = RemoteControlPlane::new(&config).await;
    assert!(matches!(result, Err(ProxyError::Configuration(_))));
}
