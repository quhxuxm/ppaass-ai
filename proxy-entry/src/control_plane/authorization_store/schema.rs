use std::path::Path;

use sqlx::{Row, SqlitePool};

use super::database_config_error;
use crate::error::{ProxyError, Result};

const SCHEMA_VERSION: i64 = 1;

pub(super) struct StoredMetadata {
    pub revision: Option<u64>,
    pub registry_url: Option<String>,
    pub entry_id: Option<String>,
}

pub(super) async fn initialize_schema(pool: &SqlitePool, path: &Path) -> Result<()> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| database_config_error(path, "开始初始化事务", error))?;
    for statement in [
        "CREATE TABLE authorization_schema_version (\
         singleton INTEGER PRIMARY KEY CHECK(singleton = 1), version INTEGER NOT NULL)",
        "CREATE TABLE authorization_snapshot_metadata (\
         singleton INTEGER PRIMARY KEY CHECK(singleton = 1), revision INTEGER, \
         registry_url TEXT, entry_id TEXT, \
         CHECK((revision IS NULL AND registry_url IS NULL AND entry_id IS NULL) OR \
               (revision IS NOT NULL AND revision >= 0 AND registry_url IS NOT NULL \
                AND entry_id IS NOT NULL)))",
        &authorization_table_sql("authorization_snapshot_users"),
        &authorization_table_sql("authorization_snapshot_staging"),
        "INSERT INTO authorization_schema_version (singleton, version) VALUES (1, 1)",
        "INSERT INTO authorization_snapshot_metadata \
         (singleton, revision, registry_url, entry_id) VALUES (1, NULL, NULL, NULL)",
    ] {
        sqlx::query(statement)
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_config_error(path, "初始化 schema", error))?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| database_config_error(path, "提交初始化 schema", error))?;
    Ok(())
}

pub(super) async fn validate_existing_database(pool: &SqlitePool, path: &Path) -> Result<()> {
    let version = sqlx::query_scalar::<_, i64>(
        "SELECT version FROM authorization_schema_version WHERE singleton = 1",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| database_config_error(path, "读取 schema 版本", error))?;
    if version != SCHEMA_VERSION {
        return Err(ProxyError::Configuration(format!(
            "Entry 授权数据库 schema 版本不兼容：期望 {SCHEMA_VERSION}，实际 {version}"
        )));
    }
    let metadata = load_metadata(pool, path).await?;
    validate_table_shape(pool, path, "authorization_snapshot_users").await?;
    let has_active_rows = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM authorization_snapshot_users LIMIT 1)",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| database_config_error(path, "校验已有授权快照", error))?;
    if metadata.revision.is_none() && has_active_rows {
        return Err(ProxyError::Configuration(
            "Entry 授权数据库尚未提交快照，但 active 表不为空".to_string(),
        ));
    }
    validate_table_shape(pool, path, "authorization_snapshot_staging").await
}

pub(super) async fn load_metadata(pool: &SqlitePool, path: &Path) -> Result<StoredMetadata> {
    let row = sqlx::query(
        "SELECT revision, registry_url, entry_id FROM authorization_snapshot_metadata \
         WHERE singleton = 1",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| database_config_error(path, "读取快照 metadata", error))?;
    let revision = row
        .try_get::<Option<i64>, _>("revision")
        .map_err(|error| database_config_error(path, "解析快照 revision", error))?
        .map(u64::try_from)
        .transpose()
        .map_err(|error| {
            ProxyError::Configuration(format!("Entry 授权数据库 revision 无效：{error}"))
        })?;
    Ok(StoredMetadata {
        revision,
        registry_url: row
            .try_get("registry_url")
            .map_err(|error| database_config_error(path, "解析快照 Registry 身份", error))?,
        entry_id: row
            .try_get("entry_id")
            .map_err(|error| database_config_error(path, "解析快照 Entry 身份", error))?,
    })
}

async fn validate_table_shape(pool: &SqlitePool, path: &Path, table: &str) -> Result<()> {
    let statement = format!(
        "SELECT username, public_key_pem, permissions_json, enabled, key_version, expires_at \
         FROM {table} LIMIT 0"
    );
    sqlx::query(&statement)
        .execute(pool)
        .await
        .map_err(|error| database_config_error(path, "校验 staging schema", error))?;
    Ok(())
}

fn authorization_table_sql(table: &str) -> String {
    format!(
        "CREATE TABLE {table} (username TEXT PRIMARY KEY NOT NULL, \
         public_key_pem TEXT NOT NULL, permissions_json TEXT NOT NULL, \
         enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)), \
         key_version INTEGER NOT NULL CHECK(key_version >= 1), expires_at INTEGER)"
    )
}
