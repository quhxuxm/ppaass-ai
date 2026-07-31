mod files;
mod schema;
mod validation;

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use proxy_control_protocol::AuthorizationSnapshot;
use sqlx::SqlitePool;

use self::{
    files::{open_database, tighten_database_permissions},
    schema::{initialize_schema, load_metadata, validate_existing_database},
    validation::{user_from_row, validate_authorizations},
};
use crate::{
    config::UserConfig,
    error::{ProxyError, Result},
};

pub(super) struct AuthorizationStore {
    pool: SqlitePool,
    path: PathBuf,
    registry_url: String,
    entry_id: String,
    snapshot_loaded: AtomicBool,
    initial_revision: Option<u64>,
}

impl AuthorizationStore {
    pub async fn open(path: &Path, registry_url: &str, entry_id: &str) -> Result<Self> {
        let (pool, is_new) = open_database(path).await?;
        if is_new {
            initialize_schema(&pool, path).await?;
        } else {
            validate_existing_database(&pool, path).await?;
        }
        tighten_database_permissions(path)?;
        let metadata = load_metadata(&pool, path).await?;
        let identity_matches = metadata
            .revision
            .is_some_and(|_| metadata.registry_url.as_deref() == Some(registry_url))
            && metadata.entry_id.as_deref() == Some(entry_id);
        sqlx::query("DELETE FROM authorization_snapshot_staging")
            .execute(&pool)
            .await
            .map_err(|error| database_config_error(path, "清理残留 staging", error))?;
        Ok(Self {
            pool,
            path: path.to_path_buf(),
            registry_url: registry_url.to_string(),
            entry_id: entry_id.to_string(),
            snapshot_loaded: AtomicBool::new(identity_matches),
            initial_revision: identity_matches.then_some(metadata.revision).flatten(),
        })
    }

    pub fn initial_revision(&self) -> Option<u64> {
        self.initial_revision
    }

    pub async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        if !self.snapshot_loaded.load(Ordering::Acquire) {
            return Err(ProxyError::ControlPlane(
                "当前 Registry 的授权快照尚未成功加载".to_string(),
            ));
        }
        let row = sqlx::query(
            "SELECT username, public_key_pem, permissions_json, enabled, key_version, expires_at \
             FROM authorization_snapshot_users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| database_runtime_error(&self.path, "查询用户授权", error))?;
        row.as_ref().map(user_from_row).transpose()
    }

    pub async fn clear_staging(&self) -> Result<()> {
        sqlx::query("DELETE FROM authorization_snapshot_staging")
            .execute(&self.pool)
            .await
            .map_err(|error| database_runtime_error(&self.path, "清理授权 staging", error))?;
        Ok(())
    }

    pub async fn stage_page(&self, authorizations: &[AuthorizationSnapshot]) -> Result<()> {
        validate_authorizations(authorizations)?;
        let mut transaction =
            self.pool.begin().await.map_err(|error| {
                database_runtime_error(&self.path, "开始写入授权分页事务", error)
            })?;
        for authorization in authorizations {
            let permissions_json =
                serde_json::to_string(&authorization.permissions).map_err(|error| {
                    ProxyError::ControlPlane(format!("序列化授权权限失败：{error}"))
                })?;
            insert_authorization(
                &self.path,
                &mut transaction,
                authorization,
                permissions_json,
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| database_runtime_error(&self.path, "提交授权分页", error))?;
        Ok(())
    }

    pub async fn activate_staging(&self, revision: u64) -> Result<()> {
        let revision = i64::try_from(revision).map_err(|_| {
            ProxyError::ControlPlane("Registry 授权快照 revision 超出 SQLite 范围".to_string())
        })?;
        let mut transaction =
            self.pool.begin().await.map_err(|error| {
                database_runtime_error(&self.path, "开始切换授权快照事务", error)
            })?;
        sqlx::query("DELETE FROM authorization_snapshot_users")
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_runtime_error(&self.path, "清理旧授权快照", error))?;
        sqlx::query(
            "INSERT INTO authorization_snapshot_users \
             (username, public_key_pem, permissions_json, enabled, key_version, expires_at) \
             SELECT username, public_key_pem, permissions_json, enabled, key_version, expires_at \
             FROM authorization_snapshot_staging",
        )
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_runtime_error(&self.path, "激活授权快照", error))?;
        let updated = sqlx::query(
            "UPDATE authorization_snapshot_metadata \
             SET revision = ?, registry_url = ?, entry_id = ? WHERE singleton = 1",
        )
        .bind(revision)
        .bind(&self.registry_url)
        .bind(&self.entry_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_runtime_error(&self.path, "更新授权快照 metadata", error))?;
        if updated.rows_affected() != 1 {
            return Err(ProxyError::ControlPlane(
                "Entry 授权数据库缺少 metadata 单例行".to_string(),
            ));
        }
        sqlx::query("DELETE FROM authorization_snapshot_staging")
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_runtime_error(&self.path, "清理已激活 staging", error))?;
        transaction
            .commit()
            .await
            .map_err(|error| database_runtime_error(&self.path, "提交授权快照切换", error))?;
        self.snapshot_loaded.store(true, Ordering::Release);
        Ok(())
    }
}

async fn insert_authorization(
    path: &Path,
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    authorization: &AuthorizationSnapshot,
    permissions_json: String,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO authorization_snapshot_staging \
         (username, public_key_pem, permissions_json, enabled, key_version, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&authorization.username)
    .bind(&authorization.public_key_pem)
    .bind(permissions_json)
    .bind(authorization.enabled)
    .bind(authorization.key_version)
    .bind(authorization.expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_runtime_error(path, "写入用户授权分页", error))?;
    Ok(())
}

pub(super) fn database_config_error(
    path: &Path,
    operation: &str,
    error: sqlx::Error,
) -> ProxyError {
    ProxyError::Configuration(format!(
        "{operation} Entry 授权数据库 {} 失败：{error}",
        path.display()
    ))
}

fn database_runtime_error(path: &Path, operation: &str, error: sqlx::Error) -> ProxyError {
    ProxyError::ControlPlane(format!(
        "{operation} Entry 授权数据库 {} 失败：{error}",
        path.display()
    ))
}
