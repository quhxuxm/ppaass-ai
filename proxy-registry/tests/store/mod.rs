use protocol::RsaKeyPair;
use proxy_registry::*;
#[cfg(unix)]
use sqlx::sqlite::SqliteJournalMode;
use sqlx::{
    Row, Sqlite, Transaction,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

pub(super) const TEST_PROXY_ADDRESS_ID: &str = "pxy_test";
pub(super) const SQLITE_SCHEMA_VERSION: i64 = 15;
pub(super) const KEY_ENCRYPTION_VERIFIER_KEY: &str = "proxy_web_key_encryption_verifier_v1";
pub(super) const ACCESS_LOG_RETENTION_DAYS_KEY: &str = "access_log_retention_days";
pub(super) const COMPROMISED_BUNDLED_DEMO_PUBLIC_KEYS: [&str; 1] = [r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtm6UwXI/ZmUrWPF9gkXs
vmnh/77vci16aGJBZv9BM7+wuY2ml7mvdYFbGVPiKB9LC4tudvGmv298XuecKxuz
HRoSwspj2qnr8wA1qsjHlVKaACVKKSgajlRE4bkBxylyfIZmXGOQrrzvuu61Ku3S
xAPMzdW5EUIaHHJ5bd01ZfEJ6vsJKLG8cT9Iyj+ssED8pRTRp2jbtVJ/sNqc0tS1
MznDGEVOa8UzyZUa8aGaQjGQExAzRCCDzh3ceSedIhp4ySs6Kud7nsQSgFVc0pxc
PxzO8/ImXr5KWigaTnkfTVGFzFHrzgTdqPJiLtNRPCmxQAMZpu/U9nxCA5YY2xR5
ywIDAQAB
-----END PUBLIC KEY-----"#];

pub(super) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub(super) async fn table_columns(
    transaction: &mut Transaction<'_, Sqlite>,
    table: &str,
) -> std::result::Result<Vec<String>, sqlx::Error> {
    let query  = sqlx::AssertSqlSafe(format!("PRAGMA table_info({table})"));
    let rows = sqlx::query(query)
        .fetch_all(&mut **transaction)
        .await?;
    rows.into_iter()
        .map(|row| row.try_get::<String, _>("name"))
        .collect()
}

#[cfg(unix)]
pub(super) fn database_sidecar_files(database_path: &Path) -> [PathBuf; 3] {
    let auxiliary_path = |suffix: &str| {
        let mut path = database_path.as_os_str().to_os_string();
        path.push(suffix);
        PathBuf::from(path)
    };
    [
        auxiliary_path("-wal"),
        auxiliary_path("-shm"),
        auxiliary_path("-journal"),
    ]
}

#[cfg(unix)]
pub(super) fn database_files(database_path: &Path) -> [PathBuf; 4] {
    let [wal, shm, journal] = database_sidecar_files(database_path);
    [database_path.to_path_buf(), wal, shm, journal]
}

pub(super) async fn test_store() -> (TempDir, SqliteUserRepository) {
    let directory = TempDir::new().unwrap();
    let store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
        .await
        .unwrap();
    store
        .create_proxy_address(NewProxyAddress {
            proxy_address_id: TEST_PROXY_ADDRESS_ID.to_string(),
            label: "Test Proxy".to_string(),
            address: "127.0.0.1:8080".to_string(),
            enabled: true,
        })
        .await
        .unwrap();
    (directory, store)
}

pub(super) fn public_key() -> String {
    RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap()
}

pub(super) async fn drop_v8_proxy_address_tables(store: &SqliteUserRepository) {
    sqlx::query("DROP TABLE account_proxy_addresses")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TABLE proxy_addresses")
        .execute(store.pool())
        .await
        .unwrap();
}

pub(super) async fn drop_v9_key_request_columns(store: &SqliteUserRepository) {
    sqlx::query("ALTER TABLE key_generation_requests DROP COLUMN reviewer_login_name")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("ALTER TABLE key_generation_requests DROP COLUMN rejection_reason")
        .execute(store.pool())
        .await
        .unwrap();
}

pub(super) async fn drop_v10_account_disable_audits(store: &SqliteUserRepository) {
    sqlx::query("DROP TABLE account_disable_audits")
        .execute(store.pool())
        .await
        .unwrap();
}

pub(super) async fn drop_v11_operation_audits(store: &SqliteUserRepository) {
    sqlx::query("DROP TABLE operation_audits")
        .execute(store.pool())
        .await
        .unwrap();
}

pub(super) async fn drop_v12_registry_coordination_tables(store: &SqliteUserRepository) {
    sqlx::query("DROP TABLE agent_web_session_handoffs")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TABLE registry_agent_events")
        .execute(store.pool())
        .await
        .unwrap();
}

pub(super) async fn drop_v13_proxy_entry_columns(store: &SqliteUserRepository) {
    for statement in [
        "DROP INDEX idx_proxy_addresses_entry_heartbeat",
        "DROP INDEX idx_proxy_addresses_entry_id",
        "ALTER TABLE proxy_addresses DROP COLUMN entry_last_heartbeat_at",
        "ALTER TABLE proxy_addresses DROP COLUMN entry_first_registered_at",
        "ALTER TABLE proxy_addresses DROP COLUMN entry_version",
        "ALTER TABLE proxy_addresses DROP COLUMN entry_id",
    ] {
        sqlx::query(statement).execute(store.pool()).await.unwrap();
    }
}

pub(super) fn account_actor(account_id: &str, login_name: &str) -> AccountActor {
    AccountActor {
        account_id: account_id.to_string(),
        login_name: login_name.to_string(),
    }
}

pub(super) fn managed_user(
    account_id: &str,
    login_name: &str,
    username: &str,
    role: AccountRole,
    external_identity: Option<ExternalIdentity>,
) -> NewManagedUser {
    NewManagedUser {
        account_id: account_id.to_string(),
        login_name: login_name.to_string(),
        password_hash: Some("$argon2id$test".to_string()),
        role,
        status: AccountStatus::Active,
        display_name: Some(login_name.to_string()),
        email: None,
        avatar_url: None,
        profile: NewUser::new(username, public_key(), UserOrigin::Admin),
        encrypted_private_key: b"encrypted-private-key".to_vec(),
        external_identity,
        proxy_address_ids: vec![TEST_PROXY_ADDRESS_ID.to_string()],
        created_by: None,
        audit_reason: None,
    }
}

pub(super) fn user_account(account_id: &str, login_name: &str) -> NewUserAccount {
    NewUserAccount {
        account_id: account_id.to_string(),
        login_name: login_name.to_string(),
        password_hash: Some("$argon2id$test".to_string()),
        display_name: Some(login_name.to_string()),
        email: None,
        avatar_url: None,
        external_identity: None,
    }
}

pub(super) async fn create_admin(store: &SqliteUserRepository, account_id: &str) {
    let outcome = store
        .bootstrap_admin_if_absent(NewAdminAccount {
            account_id: account_id.to_string(),
            login_name: account_id.to_string(),
            password_hash: Some("$argon2id$test".to_string()),
            display_name: None,
            email: None,
            avatar_url: None,
        })
        .await
        .unwrap();
    assert!(matches!(outcome, BootstrapOutcome::Created(_)));
}

pub(super) fn initial_approval(
    request_id: &str,
    reviewer_account_id: &str,
    username: &str,
    expires_at: i64,
) -> KeyRequestApproval {
    KeyRequestApproval {
        request_id: request_id.to_string(),
        reviewer_account_id: reviewer_account_id.to_string(),
        expires_at,
        proxy_address_ids: vec![TEST_PROXY_ADDRESS_ID.to_string()],
        material: ApprovedKeyMaterial::Initial {
            profile: NewUser::new(username, public_key(), UserOrigin::Local),
            encrypted_private_key: b"encrypted-private-key".to_vec(),
        },
        audit_reason: "测试审批".to_string(),
    }
}

mod access;
mod account_creation;
mod account_security;
mod coordination;
mod device_authorization;
mod key_binding;
mod key_requests;
mod key_requests_admin;
mod migrations;
mod permissions;
mod permissions_migration;
mod proxy_address_migration;
mod proxy_addresses;
mod proxy_entries;
mod proxy_selection_migration;
mod read_only;
mod users;
