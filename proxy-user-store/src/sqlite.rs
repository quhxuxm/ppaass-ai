use crate::{
    AccessLogRepository, AccessLogSettings, AccessProtocol, AccessRecord, AccountRepository,
    AccountRole, AccountStatus, AgentDeviceAuthorization, AgentDeviceAuthorizationClaim,
    AgentDeviceAuthorizationDecision, AgentDeviceAuthorizationFinalize,
    AgentDeviceAuthorizationPoll, AgentDeviceAuthorizationRepository,
    AgentDeviceAuthorizationStatus, ApprovedKeyMaterial, BootstrapOutcome,
    DEFAULT_ACCESS_LOG_RETENTION_DAYS, EncryptedPrivateKey, ExternalIdentity, KeyEncryptionBinding,
    KeyGenerationRequest, KeyPairRotation, KeyRequestApproval, KeyRequestApprovalResult,
    KeyRequestKind, KeyRequestStatus, LoginRecord, MAX_ACCESS_LOG_QUERY_LIMIT,
    MAX_ACCESS_LOG_RETENTION_DAYS, MIN_ACCESS_LOG_RETENTION_DAYS, ManagedUser, ManagedUserUpdate,
    NewAccessRecord, NewAdminAccount, NewAgentDeviceAuthorization, NewKeyGenerationRequest,
    NewManagedUser, NewUser, NewUserAccount, Result, UserOrigin, UserRecord, UserRepository,
    UserRepositoryError, UserUpdate, ValidationError, WebAccount, normalize_permissions,
    normalize_public_key_pem, normalize_username, validate_user,
};
use async_trait::async_trait;
use sqlx::{
    Row, Sqlite, SqliteConnection, SqlitePool, Transaction,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
    },
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{info, instrument, warn};

const ACCESS_LOG_RETENTION_DAYS_KEY: &str = "access_log_retention_days";
const KEY_ENCRYPTION_VERIFIER_KEY: &str = "proxy_web_key_encryption_verifier_v1";
const SQLITE_SCHEMA_VERSION: i64 = 5;
const MAX_ACCOUNT_ID_BYTES: usize = 128;
const MAX_PROVIDER_BYTES: usize = 64;
const MAX_PROVIDER_SUBJECT_BYTES: usize = 512;
const MAX_PASSWORD_HASH_BYTES: usize = 4096;
const MAX_DISPLAY_NAME_BYTES: usize = 256;
const MAX_EMAIL_BYTES: usize = 320;
const MAX_AVATAR_URL_BYTES: usize = 2048;
const MAX_PRIVATE_KEY_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_ACCESS_TARGET_HOST_BYTES: usize = 1_024;
const DEVICE_CODE_HASH_BYTES: usize = 43;
const USER_CODE_HASH_BYTES: usize = 43;
const MAX_AGENT_CLIENT_NAME_BYTES: usize = 128;
const MAX_AGENT_PLATFORM_BYTES: usize = 32;
const MAX_ACTIVE_DEVICE_AUTHORIZATIONS: i64 = 10_000;
const MAX_USER_ACCOUNTS: i64 = 100_000;
const DEVICE_AUTHORIZATION_HISTORY_SECONDS: i64 = 86_400;
const DEVICE_AUTHORIZATION_MAINTENANCE_SECONDS: i64 = 30;
// These two legacy demo keypairs were committed to the public repository. Matching legacy
// profiles are disabled on every writable Web startup so an already-imported production
// database cannot silently keep accepting the compromised private keys. A legitimate user can
// recover only by rotating to a different key through the normal admin workflow.
const COMPROMISED_BUNDLED_DEMO_PUBLIC_KEYS: [&str; 2] = [
    r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtm6UwXI/ZmUrWPF9gkXs
vmnh/77vci16aGJBZv9BM7+wuY2ml7mvdYFbGVPiKB9LC4tudvGmv298XuecKxuz
HRoSwspj2qnr8wA1qsjHlVKaACVKKSgajlRE4bkBxylyfIZmXGOQrrzvuu61Ku3S
xAPMzdW5EUIaHHJ5bd01ZfEJ6vsJKLG8cT9Iyj+ssED8pRTRp2jbtVJ/sNqc0tS1
MznDGEVOa8UzyZUa8aGaQjGQExAzRCCDzh3ceSedIhp4ySs6Kud7nsQSgFVc0pxc
PxzO8/ImXr5KWigaTnkfTVGFzFHrzgTdqPJiLtNRPCmxQAMZpu/U9nxCA5YY2xR5
ywIDAQAB
-----END PUBLIC KEY-----"#,
    r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0yqkQjUeFaYbsJxiUJtW
s3Jd22uAg7fyGyZZAtzI6JNmF/L8zeHxoWhUjEOUuwHmRn4AaEvgSbjFIwnPuVGm
qCAd8h31379p3Mp5ahA4IMDarb6PUoKDDIxSAYUfkRtpjNZilPVeh2eFWyH41NrS
NyuKhxQ/aMnVoDrwuEwJQM5K8hdo0pwnfQv3yNtX16E3woe/vTb5f2fvPMZfz0sQ
rqKBednzxoJ3Zd5SCHBBTnD4u6VVzKlkQc9qpsSIkhJ8jQK4SsxCXlKH2vrsYAHj
Xsg2dea7zeV8pRw0uL010Cx208clFEtV3EMdgY2iSpbTW+gOuhgciVdzjR/EAXtH
lwIDAQAB
-----END PUBLIC KEY-----"#,
];

/// Unix file permissions applied to the SQLite database and its sidecar files.
///
/// `OwnerAndGroup` only adds group read/write bits. It intentionally does not
/// change ownership: deployments using separate service users must place the
/// database in a trusted setgid directory owned by their shared group. On
/// non-Unix platforms this policy is accepted but file access remains governed
/// by the platform's native ACLs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SqliteFilePermissions {
    /// Restrict the database, WAL, SHM and rollback journal to the owner (`0600`).
    #[default]
    OwnerOnly,
    /// Permit the owner to write and the inherited group to read (`0640`).
    OwnerReadWriteGroupRead,
    /// Permit both the owner and the inherited group to access the files (`0660`).
    OwnerAndGroup,
}

#[cfg(unix)]
impl SqliteFilePermissions {
    pub(crate) const fn unix_mode(self) -> u32 {
        match self {
            Self::OwnerOnly => 0o600,
            Self::OwnerReadWriteGroupRead => 0o640,
            Self::OwnerAndGroup => 0o660,
        }
    }
}

const USER_SELECT: &str = "username, public_key_pem, permissions, enabled, origin, \
                           key_version, expires_at, created_at, updated_at";
const ACCOUNT_SELECT: &str = "account_id, login_name, role, status, linked_username, \
                              display_name, email, avatar_url, auth_version, last_login_at, \
                              created_at, updated_at";
const QUALIFIED_ACCOUNT_SELECT: &str = "a.account_id, a.login_name, a.role, a.status, \
                                        a.linked_username, a.display_name, a.email, a.avatar_url, \
                                        a.auth_version, a.last_login_at, a.created_at, a.updated_at";
const KEY_REQUEST_SELECT: &str = "request_id, account_id, kind, status, expected_key_version, \
                                  reviewer_account_id, requested_at, reviewed_at, \
                                  approved_expires_at";
const ACCESS_RECORD_SELECT: &str = "record_id, username, protocol, target_host, target_port, \
                                    access_count, accessed_at";
const DEVICE_AUTHORIZATION_SELECT: &str = "device_code_hash, user_code_hash, client_name, \
                                           platform, status, authorized_account_id, \
                                           authorized_auth_version, created_at, expires_at, \
                                           authorized_at, consumed_at, last_polled_at";

#[derive(Debug, Clone)]
pub struct SqliteUserRepository {
    pool: SqlitePool,
    path: PathBuf,
    file_permissions: SqliteFilePermissions,
    max_user_accounts: i64,
    device_authorization_maintenance: Arc<Mutex<DeviceAuthorizationMaintenance>>,
}

#[derive(Debug)]
struct DeviceAuthorizationMaintenance {
    active_count: i64,
    next_run_at: i64,
}

impl SqliteUserRepository {
    #[instrument(skip(path), fields(database = %path.as_ref().display()))]
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        Self::connect_with_permissions(path, SqliteFilePermissions::OwnerOnly).await
    }

    /// Opens an already-initialized user database without any write capability.
    ///
    /// This is the only constructor the Proxy process should use. It neither creates
    /// directories/files nor runs migrations/imports, and every SQLite connection has both
    /// `SQLITE_OPEN_READONLY` and `PRAGMA query_only=ON`. Proxy Web must initialize and migrate
    /// the database before Proxy starts.
    #[instrument(skip(path), fields(database = %path.as_ref().display(), read_only = true))]
    pub async fn connect_read_only(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "只读用户数据库 {} 不存在或无法访问：{error}",
                    path.display()
                ),
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "只读用户数据库路径不是普通文件（拒绝符号链接）：{}",
                    path.display()
                ),
            )
            .into());
        }

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .read_only(true)
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(5))
            .foreign_keys(true)
            .pragma("query_only", "ON");
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await?;

        let schema_version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await?;
        if schema_version != SQLITE_SCHEMA_VERSION {
            return Err(UserRepositoryError::InvalidSchema(format!(
                "Proxy 只读用户数据库版本必须为 {SQLITE_SCHEMA_VERSION}，实际为 \
                 {schema_version}；请先启动 Proxy Web 完成迁移"
            )));
        }
        // Proxy authentication only needs this table. A zero-row query validates its complete
        // runtime contract without loading user or key data.
        sqlx::query(&format!("SELECT {USER_SELECT} FROM users LIMIT 0"))
            .execute(&pool)
            .await?;

        let store = Self {
            pool,
            path,
            // A read-only repository never applies this mode; retain a deterministic value so
            // the common repository representation does not expose SQLite details to callers.
            file_permissions: SqliteFilePermissions::OwnerOnly,
            max_user_accounts: MAX_USER_ACCOUNTS,
            device_authorization_maintenance: Arc::new(Mutex::new(
                DeviceAuthorizationMaintenance {
                    active_count: 0,
                    next_run_at: i64::MIN,
                },
            )),
        };
        info!(
            database = %store.path.display(),
            schema_version = SQLITE_SCHEMA_VERSION,
            "SQLite 用户数据库已以强制只读模式打开"
        );
        Ok(store)
    }

    /// Opens the SQLite repository with an explicit Unix file permission policy.
    ///
    /// The policy is applied before SQLite opens the database and again after
    /// migration. Existing database, WAL, SHM and rollback journal files are
    /// opened without following a terminal symlink before their modes are
    /// changed. SQLite derives newly-created sidecar modes from the database
    /// file, so they inherit the same `0600` or `0660` policy.
    #[instrument(
        skip(path),
        fields(
            database = %path.as_ref().display(),
            file_permissions = ?file_permissions
        )
    )]
    pub async fn connect_with_permissions(
        path: impl AsRef<Path>,
        file_permissions: SqliteFilePermissions,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        Self::prepare_database_files(&path, file_permissions)?;

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await?;

        let store = Self {
            pool,
            path,
            file_permissions,
            max_user_accounts: MAX_USER_ACCOUNTS,
            device_authorization_maintenance: Arc::new(Mutex::new(
                DeviceAuthorizationMaintenance {
                    active_count: 0,
                    next_run_at: i64::MIN,
                },
            )),
        };
        store.migrate().await?;
        store.apply_file_permissions()?;
        info!(
            database = %store.path.display(),
            schema_version = SQLITE_SCHEMA_VERSION,
            file_permissions = ?store.file_permissions,
            "SQLite 用户数据库已就绪"
        );
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    async fn migrate(&self) -> Result<()> {
        // Proxy 与 Web 可能同时启动。IMMEDIATE 在读取版本前取得写锁，确保只有一个
        // 进程执行升级，另一个进程随后会看到已经提交的新版本。
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let schema_version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut *transaction)
            .await?;
        if schema_version > SQLITE_SCHEMA_VERSION {
            return Err(UserRepositoryError::InvalidSchema(format!(
                "数据库版本 {schema_version} 高于当前支持版本 {SQLITE_SCHEMA_VERSION}"
            )));
        }

        if schema_version < 2 {
            migrate_users_table(&mut transaction, schema_version).await?;
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS app_metadata (
                    key TEXT NOT NULL PRIMARY KEY,
                    value TEXT NOT NULL
                )
                "#,
            )
            .execute(&mut *transaction)
            .await?;
            create_v2_tables(&mut transaction).await?;
        }
        if schema_version < 3 {
            create_v3_tables(&mut transaction).await?;
        }
        if schema_version < 4 {
            migrate_access_records_to_v4(&mut transaction).await?;
        }
        if schema_version < 5 {
            create_v5_tables(&mut transaction).await?;
        }
        ensure_v5_indexes(&mut transaction).await?;
        let revoked_compromised_profiles =
            revoke_compromised_bundled_demo_profiles(&mut transaction).await?;

        validate_schema(&mut transaction).await?;
        if sqlx::query("PRAGMA foreign_key_check")
            .fetch_optional(&mut *transaction)
            .await?
            .is_some()
        {
            return Err(UserRepositoryError::InvalidSchema(
                "数据库外键完整性检查失败".to_string(),
            ));
        }

        if schema_version < SQLITE_SCHEMA_VERSION {
            // 版本号是迁移的提交标记，必须最后写入。
            sqlx::query("PRAGMA user_version = 5")
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        if revoked_compromised_profiles != 0 {
            warn!(
                profiles = revoked_compromised_profiles,
                "已停用使用公开仓库泄露私钥的 legacy 用户；必须轮换密钥后再启用"
            );
        }
        Ok(())
    }

    /// 使用完整的新用户模型创建 Proxy profile。
    pub async fn create_user_record(&self, user: NewUser) -> Result<UserRecord> {
        let user = normalize_new_user(user)?;
        let now = now();
        let result = sqlx::query(
            "INSERT INTO users \
             (username, public_key_pem, permissions, enabled, origin, key_version, \
              expires_at, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?) \
             ON CONFLICT(username) DO NOTHING",
        )
        .bind(&user.username)
        .bind(&user.public_key_pem)
        .bind(encode_permissions(&user.permissions))
        .bind(user.enabled)
        .bind(user.origin.as_str())
        .bind(user.expires_at)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::Conflict(user.username));
        }
        info!(username = user.username, "Proxy 用户已创建");
        Ok(UserRecord {
            username: user.username,
            public_key_pem: user.public_key_pem,
            permissions: user.permissions,
            enabled: user.enabled,
            origin: user.origin,
            key_version: 1,
            expires_at: user.expires_at,
            created_at: now,
            updated_at: now,
        })
    }

    #[instrument(skip(self), fields(username))]
    async fn get_user(&self, username: &str) -> Result<Option<UserRecord>> {
        let username = normalize_username(username)?;
        let query = format!("SELECT {USER_SELECT} FROM users WHERE username = ?");
        let row = sqlx::query(&query)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_user).transpose()
    }

    #[instrument(skip(self))]
    async fn list_users(&self) -> Result<Vec<UserRecord>> {
        let query = format!("SELECT {USER_SELECT} FROM users ORDER BY username COLLATE BINARY");
        sqlx::query(&query)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(row_to_user)
            .collect()
    }

    #[instrument(skip(self, public_key_pem), fields(username))]
    async fn create_user(
        &self,
        username: &str,
        public_key_pem: &str,
        expires_at: Option<i64>,
    ) -> Result<UserRecord> {
        let mut user = NewUser::new(username, public_key_pem, UserOrigin::Admin);
        user.expires_at = expires_at;
        self.create_user_record(user).await
    }

    #[instrument(skip(self, update), fields(username))]
    async fn update_user(&self, username: &str, update: UserUpdate) -> Result<UserRecord> {
        let username = normalize_username(username)?;
        if update.is_empty() {
            return Err(ValidationError::EmptyUpdate.into());
        }
        let public_key_pem = update
            .public_key_pem
            .as_deref()
            .map(normalize_public_key_pem)
            .transpose()?;
        let permissions = update
            .permissions
            .as_deref()
            .map(normalize_permissions)
            .transpose()?;

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let query = format!("SELECT {USER_SELECT} FROM users WHERE username = ?");
        let mut user = sqlx::query(&query)
            .bind(&username)
            .fetch_optional(&mut *transaction)
            .await?
            .map(row_to_user)
            .transpose()?
            .ok_or_else(|| UserRepositoryError::NotFound(username.clone()))?;

        let key_changed = public_key_pem
            .as_ref()
            .is_some_and(|key| key != &user.public_key_pem);
        if let Some(public_key_pem) = public_key_pem {
            user.public_key_pem = public_key_pem;
        }
        if let Some(permissions) = permissions {
            user.permissions = permissions;
        }
        if let Some(enabled) = update.enabled {
            user.enabled = enabled;
        }
        if let Some(expires_at) = update.expires_at {
            user.expires_at = expires_at;
        }
        if key_changed {
            user.key_version = user.key_version.checked_add(1).ok_or_else(|| {
                UserRepositoryError::InvalidSchema(format!(
                    "用户 {} 的 key_version 已溢出",
                    user.username
                ))
            })?;
        }
        user.updated_at = now();

        sqlx::query(
            "UPDATE users SET public_key_pem = ?, permissions = ?, enabled = ?, \
             key_version = ?, expires_at = ?, updated_at = ? WHERE username = ?",
        )
        .bind(&user.public_key_pem)
        .bind(encode_permissions(&user.permissions))
        .bind(user.enabled)
        .bind(user.key_version)
        .bind(user.expires_at)
        .bind(user.updated_at)
        .bind(&user.username)
        .execute(&mut *transaction)
        .await?;

        if key_changed {
            // 独立更新公钥后，原托管私钥不再可信；只有 rotate_keypair 能原子保留二者。
            sqlx::query("DELETE FROM user_private_keys WHERE username = ?")
                .bind(&user.username)
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        info!(
            username = user.username,
            key_changed, "Proxy 用户配置已更新"
        );
        Ok(user)
    }

    #[instrument(skip(self), fields(username))]
    async fn delete_user(&self, username: &str) -> Result<()> {
        let username = normalize_username(username)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let account_query =
            format!("SELECT {ACCOUNT_SELECT} FROM web_accounts WHERE linked_username = ?");
        let linked_account = sqlx::query(&account_query)
            .bind(&username)
            .fetch_optional(&mut *transaction)
            .await?
            .map(row_to_account)
            .transpose()?;

        if let Some(account) = &linked_account {
            guard_last_admin(&mut transaction, account, None, None).await?;
            sqlx::query("DELETE FROM web_accounts WHERE account_id = ?")
                .bind(&account.account_id)
                .execute(&mut *transaction)
                .await?;
        }
        let result = sqlx::query("DELETE FROM users WHERE username = ?")
            .bind(&username)
            .execute(&mut *transaction)
            .await?;
        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(username));
        }
        transaction.commit().await?;
        info!(username, "Proxy 用户已删除");
        Ok(())
    }

    #[cfg(unix)]
    fn prepare_database_files(
        database_path: &Path,
        file_permissions: SqliteFilePermissions,
    ) -> Result<()> {
        let mode = file_permissions.unix_mode();
        secure_open_and_set_mode(database_path, mode, true)?;
        for path in database_sidecar_files(database_path) {
            secure_open_and_set_mode(&path, mode, false)?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn prepare_database_files(
        _database_path: &Path,
        _file_permissions: SqliteFilePermissions,
    ) -> Result<()> {
        Ok(())
    }

    #[cfg(unix)]
    fn apply_file_permissions(&self) -> Result<()> {
        let mode = self.file_permissions.unix_mode();
        for path in database_files(&self.path) {
            secure_open_and_set_mode(&path, mode, false)?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn apply_file_permissions(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl UserRepository for SqliteUserRepository {
    async fn get_user(&self, username: &str) -> Result<Option<UserRecord>> {
        SqliteUserRepository::get_user(self, username).await
    }

    async fn list_users(&self) -> Result<Vec<UserRecord>> {
        SqliteUserRepository::list_users(self).await
    }

    async fn create_user(
        &self,
        username: &str,
        public_key_pem: &str,
        expires_at: Option<i64>,
    ) -> Result<UserRecord> {
        SqliteUserRepository::create_user(self, username, public_key_pem, expires_at).await
    }

    async fn update_user(&self, username: &str, update: UserUpdate) -> Result<UserRecord> {
        SqliteUserRepository::update_user(self, username, update).await
    }

    async fn delete_user(&self, username: &str) -> Result<()> {
        SqliteUserRepository::delete_user(self, username).await
    }
}

#[async_trait]
impl AccessLogRepository for SqliteUserRepository {
    #[instrument(
        skip(self, record),
        fields(username = %record.username, protocol = record.protocol.as_str())
    )]
    async fn record_access(&self, record: NewAccessRecord) -> Result<()> {
        let username = normalize_username(&record.username)?;
        let target_host = normalize_access_target_host(&record.target_host)?;
        if record.target_port == 0 {
            return Err(ValidationError::InvalidAccountField(
                "访问目标端口必须在 1..=65535 范围内".to_string(),
            )
            .into());
        }
        if record.accessed_at < 0 {
            return Err(
                ValidationError::InvalidAccountField("accessed_at 不能为负数".to_string()).into(),
            );
        }
        sqlx::query(
            "INSERT INTO user_access_records \
             (username, protocol, target_host, target_port, access_count, accessed_at) \
             VALUES (?, ?, ?, ?, 1, ?) \
             ON CONFLICT(username, target_host) DO UPDATE SET \
               protocol = CASE \
                 WHEN excluded.accessed_at >= user_access_records.accessed_at \
                 THEN excluded.protocol ELSE user_access_records.protocol END, \
               target_port = CASE \
                 WHEN excluded.accessed_at >= user_access_records.accessed_at \
                 THEN excluded.target_port ELSE user_access_records.target_port END, \
               access_count = user_access_records.access_count + 1, \
               accessed_at = MAX(user_access_records.accessed_at, excluded.accessed_at)",
        )
        .bind(username)
        .bind(record.protocol.as_str())
        .bind(target_host)
        .bind(i64::from(record.target_port))
        .bind(record.accessed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    #[instrument(skip(self), fields(username, since, limit))]
    async fn list_recent_access(
        &self,
        username: &str,
        since: i64,
        limit: u32,
    ) -> Result<Vec<AccessRecord>> {
        let username = normalize_username(username)?;
        if since < 0 {
            return Err(
                ValidationError::InvalidAccountField("since 不能为负数".to_string()).into(),
            );
        }
        if limit == 0 || limit > MAX_ACCESS_LOG_QUERY_LIMIT {
            return Err(ValidationError::InvalidAccountField(format!(
                "访问记录 limit 必须在 1..={MAX_ACCESS_LOG_QUERY_LIMIT} 范围内"
            ))
            .into());
        }
        let query = format!(
            "SELECT {ACCESS_RECORD_SELECT} FROM user_access_records \
             WHERE username = ? AND accessed_at >= ? \
             ORDER BY accessed_at DESC, record_id DESC LIMIT ?"
        );
        sqlx::query(&query)
            .bind(username)
            .bind(since)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(row_to_access_record)
            .collect()
    }

    async fn get_access_log_settings(&self) -> Result<AccessLogSettings> {
        let value: Option<String> =
            sqlx::query_scalar("SELECT value FROM app_metadata WHERE key = ?")
                .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
                .fetch_optional(&self.pool)
                .await?;
        let value = value.ok_or_else(|| {
            UserRepositoryError::InvalidSchema(
                "app_metadata 缺少 access_log_retention_days".to_string(),
            )
        })?;
        Ok(AccessLogSettings {
            retention_days: parse_retention_days(&value)?,
        })
    }

    #[instrument(skip(self), fields(retention_days))]
    async fn set_access_log_retention_days(
        &self,
        retention_days: u16,
    ) -> Result<AccessLogSettings> {
        validate_retention_days(retention_days)?;
        let result = sqlx::query("UPDATE app_metadata SET value = ? WHERE key = ?")
            .bind(retention_days.to_string())
            .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() != 1 {
            return Err(UserRepositoryError::InvalidSchema(
                "app_metadata 缺少 access_log_retention_days".to_string(),
            ));
        }
        Ok(AccessLogSettings { retention_days })
    }

    #[instrument(skip(self), fields(before))]
    async fn purge_access_records_before(&self, before: i64) -> Result<u64> {
        if before < 0 {
            return Err(
                ValidationError::InvalidAccountField("before 不能为负数".to_string()).into(),
            );
        }
        let result = sqlx::query("DELETE FROM user_access_records WHERE accessed_at < ?")
            .bind(before)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl AgentDeviceAuthorizationRepository for SqliteUserRepository {
    #[instrument(skip(self, authorization))]
    async fn create_agent_device_authorization(
        &self,
        authorization: NewAgentDeviceAuthorization,
    ) -> Result<()> {
        let device_code_hash =
            normalize_code_hash("device_code_hash", &authorization.device_code_hash)?;
        let user_code_hash = normalize_code_hash("user_code_hash", &authorization.user_code_hash)?;
        let client_name = normalize_agent_client_name(&authorization.client_name)?;
        let platform = normalize_agent_platform(&authorization.platform)?;
        if authorization.created_at < 0 || authorization.expires_at <= authorization.created_at {
            return Err(
                ValidationError::InvalidAccountField("设备授权有效期无效".to_string()).into(),
            );
        }

        let mut maintenance = self.device_authorization_maintenance.lock().await;
        if authorization.created_at >= maintenance.next_run_at {
            let history_cutoff = authorization
                .created_at
                .saturating_sub(DEVICE_AUTHORIZATION_HISTORY_SECONDS);
            let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            sqlx::query(
                "DELETE FROM agent_device_authorizations \
                 WHERE expires_at < ? OR (consumed_at IS NOT NULL AND consumed_at < ?)",
            )
            .bind(history_cutoff)
            .bind(history_cutoff)
            .execute(&mut *transaction)
            .await?;
            maintenance.active_count = sqlx::query_scalar(
                "SELECT COUNT(*) FROM agent_device_authorizations \
                 WHERE expires_at > ? AND status IN ('pending', 'authorized')",
            )
            .bind(authorization.created_at)
            .fetch_one(&mut *transaction)
            .await?;
            transaction.commit().await?;
            maintenance.next_run_at = authorization
                .created_at
                .saturating_add(DEVICE_AUTHORIZATION_MAINTENANCE_SECONDS);
        }
        if maintenance.active_count >= MAX_ACTIVE_DEVICE_AUTHORIZATIONS {
            return Err(UserRepositoryError::AgentDeviceAuthorizationCapacity);
        }

        let insert = sqlx::query(
            "INSERT INTO agent_device_authorizations \
             (device_code_hash, user_code_hash, client_name, platform, status, \
              authorized_account_id, authorized_auth_version, created_at, expires_at, \
              authorized_at, consumed_at, last_polled_at) \
             VALUES (?, ?, ?, ?, 'pending', NULL, NULL, ?, ?, NULL, NULL, NULL) \
             ON CONFLICT DO NOTHING",
        )
        .bind(device_code_hash)
        .bind(user_code_hash)
        .bind(client_name)
        .bind(platform)
        .bind(authorization.created_at)
        .bind(authorization.expires_at)
        .execute(&self.pool)
        .await?;
        if insert.rows_affected() != 1 {
            return Err(UserRepositoryError::AgentDeviceAuthorizationConflict);
        }
        maintenance.active_count = maintenance.active_count.saturating_add(1);
        Ok(())
    }

    async fn get_agent_device_authorization_by_user_code(
        &self,
        user_code_hash: &str,
        now: i64,
    ) -> Result<Option<AgentDeviceAuthorization>> {
        let user_code_hash = normalize_code_hash("user_code_hash", user_code_hash)?;
        if now < 0 {
            return Err(
                ValidationError::InvalidAccountField("当前时间不能为负数".to_string()).into(),
            );
        }
        let query = format!(
            "SELECT {DEVICE_AUTHORIZATION_SELECT} FROM agent_device_authorizations \
             WHERE user_code_hash = ?"
        );
        sqlx::query(&query)
            .bind(user_code_hash)
            .fetch_optional(&self.pool)
            .await?
            .map(row_to_agent_device_authorization)
            .transpose()
    }

    #[instrument(skip(self, user_code_hash), fields(account_id, account_auth_version))]
    async fn authorize_agent_device(
        &self,
        user_code_hash: &str,
        account_id: &str,
        account_auth_version: i64,
        now: i64,
    ) -> Result<AgentDeviceAuthorizationDecision> {
        let user_code_hash = normalize_code_hash("user_code_hash", user_code_hash)?;
        let account_id = normalize_account_id(account_id)?;
        if account_auth_version < 1 || now < 0 {
            return Err(ValidationError::InvalidAccountField(
                "设备授权账号版本或时间无效".to_string(),
            )
            .into());
        }
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let Some(record) =
            fetch_agent_device_authorization_by_user_code(&mut transaction, &user_code_hash)
                .await?
        else {
            transaction.rollback().await?;
            return Ok(AgentDeviceAuthorizationDecision::NotFound);
        };
        let decision = if record.expires_at <= now {
            AgentDeviceAuthorizationDecision::Expired
        } else {
            match record.status {
                AgentDeviceAuthorizationStatus::Pending => {
                    sqlx::query(
                        "UPDATE agent_device_authorizations SET status = 'authorized', \
                         authorized_account_id = ?, authorized_auth_version = ?, authorized_at = ? \
                         WHERE user_code_hash = ? AND status = 'pending' AND expires_at > ?",
                    )
                    .bind(&account_id)
                    .bind(account_auth_version)
                    .bind(now)
                    .bind(&user_code_hash)
                    .bind(now)
                    .execute(&mut *transaction)
                    .await?;
                    AgentDeviceAuthorizationDecision::Authorized
                }
                AgentDeviceAuthorizationStatus::Authorized
                    if record.authorized_account_id.as_deref() == Some(account_id.as_str()) =>
                {
                    AgentDeviceAuthorizationDecision::AlreadyAuthorized
                }
                AgentDeviceAuthorizationStatus::Denied => {
                    AgentDeviceAuthorizationDecision::AlreadyDenied
                }
                AgentDeviceAuthorizationStatus::Authorized
                | AgentDeviceAuthorizationStatus::Consumed => {
                    AgentDeviceAuthorizationDecision::Finalized
                }
            }
        };
        transaction.commit().await?;
        Ok(decision)
    }

    #[instrument(skip(self, user_code_hash), fields(account_id))]
    async fn deny_agent_device(
        &self,
        user_code_hash: &str,
        account_id: &str,
        now: i64,
    ) -> Result<AgentDeviceAuthorizationDecision> {
        let user_code_hash = normalize_code_hash("user_code_hash", user_code_hash)?;
        let account_id = normalize_account_id(account_id)?;
        if now < 0 {
            return Err(
                ValidationError::InvalidAccountField("当前时间不能为负数".to_string()).into(),
            );
        }
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let Some(record) =
            fetch_agent_device_authorization_by_user_code(&mut transaction, &user_code_hash)
                .await?
        else {
            transaction.rollback().await?;
            return Ok(AgentDeviceAuthorizationDecision::NotFound);
        };
        let decision = if record.expires_at <= now {
            AgentDeviceAuthorizationDecision::Expired
        } else {
            match record.status {
                AgentDeviceAuthorizationStatus::Pending => {
                    sqlx::query(
                        "UPDATE agent_device_authorizations SET status = 'denied', \
                         authorized_account_id = ?, authorized_at = ? \
                         WHERE user_code_hash = ? AND status = 'pending' AND expires_at > ?",
                    )
                    .bind(&account_id)
                    .bind(now)
                    .bind(&user_code_hash)
                    .bind(now)
                    .execute(&mut *transaction)
                    .await?;
                    AgentDeviceAuthorizationDecision::Denied
                }
                AgentDeviceAuthorizationStatus::Denied
                    if record.authorized_account_id.as_deref() == Some(account_id.as_str()) =>
                {
                    AgentDeviceAuthorizationDecision::AlreadyDenied
                }
                AgentDeviceAuthorizationStatus::Authorized => {
                    AgentDeviceAuthorizationDecision::AlreadyAuthorized
                }
                AgentDeviceAuthorizationStatus::Denied
                | AgentDeviceAuthorizationStatus::Consumed => {
                    AgentDeviceAuthorizationDecision::Finalized
                }
            }
        };
        transaction.commit().await?;
        if decision == AgentDeviceAuthorizationDecision::Denied {
            let mut maintenance = self.device_authorization_maintenance.lock().await;
            maintenance.active_count = maintenance.active_count.saturating_sub(1);
        }
        Ok(decision)
    }

    #[instrument(skip(self, device_code_hash))]
    async fn poll_agent_device_authorization(
        &self,
        device_code_hash: &str,
        now: i64,
        minimum_interval_seconds: u32,
    ) -> Result<AgentDeviceAuthorizationPoll> {
        let device_code_hash = normalize_code_hash("device_code_hash", device_code_hash)?;
        if now < 0 || minimum_interval_seconds == 0 {
            return Err(
                ValidationError::InvalidAccountField("设备授权轮询参数无效".to_string()).into(),
            );
        }
        let query = format!(
            "SELECT {DEVICE_AUTHORIZATION_SELECT} FROM agent_device_authorizations \
             WHERE device_code_hash = ?"
        );
        let initial = sqlx::query(&query)
            .bind(&device_code_hash)
            .fetch_optional(&self.pool)
            .await?
            .map(row_to_agent_device_authorization)
            .transpose()?;
        let Some(initial) = initial else {
            return Ok(AgentDeviceAuthorizationPoll::NotFound);
        };
        if let Some(result) = non_pending_device_authorization_poll(&initial, now)? {
            return Ok(result);
        }

        // 只有 pending challenge 需要写入轮询时间。无效随机 device code 和已结束
        // challenge 走上面的只读快路径，避免公开轮询接口争抢 SQLite 写锁。
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let record = sqlx::query(&query)
            .bind(&device_code_hash)
            .fetch_optional(&mut *transaction)
            .await?
            .map(row_to_agent_device_authorization)
            .transpose()?;
        let Some(record) = record else {
            transaction.rollback().await?;
            return Ok(AgentDeviceAuthorizationPoll::NotFound);
        };
        if let Some(result) = non_pending_device_authorization_poll(&record, now)? {
            transaction.commit().await?;
            return Ok(result);
        }

        let minimum_interval = i64::from(minimum_interval_seconds);
        let result = if let Some(last_polled_at) = record.last_polled_at {
            let next_allowed = last_polled_at.saturating_add(minimum_interval);
            if now < next_allowed {
                AgentDeviceAuthorizationPoll::SlowDown {
                    retry_after_seconds: u32::try_from(next_allowed - now)
                        .unwrap_or(minimum_interval_seconds),
                }
            } else {
                sqlx::query(
                    "UPDATE agent_device_authorizations SET last_polled_at = ? \
                     WHERE device_code_hash = ? AND status = 'pending'",
                )
                .bind(now)
                .bind(&device_code_hash)
                .execute(&mut *transaction)
                .await?;
                AgentDeviceAuthorizationPoll::Pending {
                    retry_after_seconds: minimum_interval_seconds,
                }
            }
        } else {
            sqlx::query(
                "UPDATE agent_device_authorizations SET last_polled_at = ? \
                 WHERE device_code_hash = ? AND status = 'pending'",
            )
            .bind(now)
            .bind(&device_code_hash)
            .execute(&mut *transaction)
            .await?;
            AgentDeviceAuthorizationPoll::Pending {
                retry_after_seconds: minimum_interval_seconds,
            }
        };
        transaction.commit().await?;
        Ok(result)
    }

    #[instrument(
        skip(self, claim),
        fields(
            account_id = %claim.account_id,
            account_auth_version = claim.account_auth_version
        )
    )]
    async fn finalize_agent_device_authorization(
        &self,
        claim: AgentDeviceAuthorizationClaim,
    ) -> Result<AgentDeviceAuthorizationFinalize> {
        let device_code_hash = normalize_code_hash("device_code_hash", &claim.device_code_hash)?;
        let account_id = normalize_account_id(&claim.account_id)?;
        let username = normalize_username(&claim.username)?;
        let permissions = normalize_permissions(&claim.permissions)?;
        if claim.account_auth_version < 1 || claim.key_version < 1 || claim.now < 0 {
            return Err(
                ValidationError::InvalidAccountField("设备授权领取参数无效".to_string()).into(),
            );
        }
        if claim
            .expires_at
            .is_some_and(|expires_at| expires_at <= claim.now)
        {
            return Ok(AgentDeviceAuthorizationFinalize::Invalidated);
        }
        let encoded_permissions = encode_permissions(&permissions);
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let query = format!(
            "SELECT {DEVICE_AUTHORIZATION_SELECT} FROM agent_device_authorizations \
             WHERE device_code_hash = ?"
        );
        let record = sqlx::query(&query)
            .bind(&device_code_hash)
            .fetch_optional(&mut *transaction)
            .await?
            .map(row_to_agent_device_authorization)
            .transpose()?;
        let Some(record) = record else {
            transaction.rollback().await?;
            return Ok(AgentDeviceAuthorizationFinalize::NotFound);
        };
        let result = if record.expires_at <= claim.now {
            AgentDeviceAuthorizationFinalize::Expired
        } else if record.authorized_account_id.as_deref() != Some(account_id.as_str())
            || record.authorized_auth_version != Some(claim.account_auth_version)
        {
            AgentDeviceAuthorizationFinalize::Invalidated
        } else {
            let snapshot_is_current: bool = sqlx::query_scalar(
                "SELECT EXISTS(\
                   SELECT 1 FROM web_accounts AS account \
                   JOIN users AS profile ON profile.username = account.linked_username \
                   JOIN user_private_keys AS private_key \
                     ON private_key.username = profile.username \
                   WHERE account.account_id = ? \
                     AND account.auth_version = ? \
                     AND account.role = 'user' \
                     AND account.status = 'active' \
                     AND profile.username = ? \
                     AND profile.permissions = ? \
                     AND profile.enabled = 1 \
                     AND profile.key_version = ? \
                     AND profile.expires_at IS ? \
                     AND (profile.expires_at IS NULL OR profile.expires_at > ?) \
                     AND private_key.key_version = profile.key_version\
                 )",
            )
            .bind(&account_id)
            .bind(claim.account_auth_version)
            .bind(&username)
            .bind(&encoded_permissions)
            .bind(claim.key_version)
            .bind(claim.expires_at)
            .bind(claim.now)
            .fetch_one(&mut *transaction)
            .await?;
            if !snapshot_is_current {
                transaction.commit().await?;
                return Ok(AgentDeviceAuthorizationFinalize::Invalidated);
            }
            match record.status {
                AgentDeviceAuthorizationStatus::Authorized => {
                    let update = sqlx::query(
                        "UPDATE agent_device_authorizations \
                         SET status = 'consumed', consumed_at = ? \
                         WHERE device_code_hash = ? AND status = 'authorized' \
                           AND authorized_account_id = ? AND authorized_auth_version = ? \
                           AND expires_at > ?",
                    )
                    .bind(claim.now)
                    .bind(&device_code_hash)
                    .bind(&account_id)
                    .bind(claim.account_auth_version)
                    .bind(claim.now)
                    .execute(&mut *transaction)
                    .await?;
                    if update.rows_affected() == 1 {
                        AgentDeviceAuthorizationFinalize::Finalized
                    } else {
                        AgentDeviceAuthorizationFinalize::Invalidated
                    }
                }
                AgentDeviceAuthorizationStatus::Consumed => {
                    AgentDeviceAuthorizationFinalize::AlreadyFinalized
                }
                AgentDeviceAuthorizationStatus::Pending
                | AgentDeviceAuthorizationStatus::Denied => {
                    AgentDeviceAuthorizationFinalize::Invalidated
                }
            }
        };
        transaction.commit().await?;
        if result == AgentDeviceAuthorizationFinalize::Finalized {
            let mut maintenance = self.device_authorization_maintenance.lock().await;
            maintenance.active_count = maintenance.active_count.saturating_sub(1);
        }
        Ok(result)
    }
}

#[async_trait]
impl AccountRepository for SqliteUserRepository {
    async fn key_encryption_binding(&self) -> Result<KeyEncryptionBinding> {
        let mut transaction = self.pool.begin().await?;
        let verifier =
            sqlx::query_scalar::<_, String>("SELECT value FROM app_metadata WHERE key = ?")
                .bind(KEY_ENCRYPTION_VERIFIER_KEY)
                .fetch_optional(&mut *transaction)
                .await?;
        let sample_private_key = sqlx::query(
            "SELECT username, encrypted_private_key, key_version, updated_at \
             FROM user_private_keys ORDER BY username COLLATE BINARY LIMIT 1",
        )
        .fetch_optional(&mut *transaction)
        .await?
        .map(row_to_encrypted_private_key)
        .transpose()?;
        transaction.commit().await?;
        Ok(KeyEncryptionBinding {
            verifier,
            sample_private_key,
        })
    }

    async fn initialize_key_encryption_verifier(&self, verifier: &str) -> Result<String> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT INTO app_metadata (key, value) VALUES (?, ?) \
             ON CONFLICT(key) DO NOTHING",
        )
        .bind(KEY_ENCRYPTION_VERIFIER_KEY)
        .bind(verifier)
        .execute(&mut *transaction)
        .await?;
        let actual =
            sqlx::query_scalar::<_, String>("SELECT value FROM app_metadata WHERE key = ?")
                .bind(KEY_ENCRYPTION_VERIFIER_KEY)
                .fetch_one(&mut *transaction)
                .await?;
        transaction.commit().await?;
        Ok(actual)
    }

    #[instrument(skip(self, admin), fields(login_name = %admin.login_name))]
    async fn bootstrap_admin_if_none(&self, admin: NewAdminAccount) -> Result<BootstrapOutcome> {
        let account_id = normalize_account_id(&admin.account_id)?;
        let login_name = normalize_username(&admin.login_name)?;
        let password_hash = normalize_password_hash(admin.password_hash)?;
        let display_name =
            normalize_optional_field("display_name", admin.display_name, MAX_DISPLAY_NAME_BYTES)?;
        let email = normalize_optional_field("email", admin.email, MAX_EMAIL_BYTES)?;
        let avatar_url =
            normalize_optional_field("avatar_url", admin.avatar_url, MAX_AVATAR_URL_BYTES)?;

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let admin_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM web_accounts WHERE role = 'admin')")
                .fetch_one(&mut *transaction)
                .await?;
        if admin_exists {
            transaction.rollback().await?;
            return Ok(BootstrapOutcome::AlreadyExists);
        }
        ensure_account_identifiers_available(&mut transaction, &account_id, &login_name, None)
            .await?;

        let timestamp = now();
        sqlx::query(
            "INSERT INTO web_accounts \
             (account_id, login_name, password_hash, role, status, linked_username, \
              display_name, email, avatar_url, auth_version, last_login_at, \
              created_at, updated_at) \
             VALUES (?, ?, ?, 'admin', 'active', NULL, ?, ?, ?, 1, NULL, ?, ?)",
        )
        .bind(&account_id)
        .bind(&login_name)
        .bind(password_hash)
        .bind(&display_name)
        .bind(&email)
        .bind(&avatar_url)
        .bind(timestamp)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
        let account = WebAccount {
            account_id,
            login_name,
            role: AccountRole::Admin,
            status: AccountStatus::Active,
            linked_username: None,
            display_name,
            email,
            avatar_url,
            auth_version: 1,
            last_login_at: None,
            created_at: timestamp,
            updated_at: timestamp,
        };
        transaction.commit().await?;
        info!(account_id = account.account_id, "首个 Web 管理员已创建");
        Ok(BootstrapOutcome::Created(account))
    }

    async fn get_account_by_login(&self, login_name: &str) -> Result<Option<WebAccount>> {
        let login_name = normalize_username(login_name)?;
        let mut connection = self.pool.acquire().await?;
        fetch_account_by_login(&mut connection, &login_name).await
    }

    async fn get_account_by_id(&self, account_id: &str) -> Result<Option<WebAccount>> {
        let account_id = normalize_account_id(account_id)?;
        let mut connection = self.pool.acquire().await?;
        fetch_account_by_id(&mut connection, &account_id).await
    }

    async fn get_account_by_external(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<WebAccount>> {
        let provider = normalize_provider(provider)?;
        let subject = normalize_provider_subject(subject)?;
        let query = format!(
            "SELECT {QUALIFIED_ACCOUNT_SELECT} FROM web_accounts a \
             INNER JOIN external_identities i ON i.account_id = a.account_id \
             WHERE i.provider = ? AND i.subject = ?"
        );
        sqlx::query(&query)
            .bind(provider)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await?
            .map(row_to_account)
            .transpose()
    }

    async fn get_login_record(&self, login_name: &str) -> Result<Option<LoginRecord>> {
        let login_name = normalize_username(login_name)?;
        let query = format!(
            "SELECT {ACCOUNT_SELECT}, password_hash FROM web_accounts WHERE login_name = ?"
        );
        let row = sqlx::query(&query)
            .bind(login_name)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            let password_hash = row.try_get("password_hash")?;
            Ok(LoginRecord {
                account: row_to_account(row)?,
                password_hash,
            })
        })
        .transpose()
    }

    async fn list_managed_users(&self) -> Result<Vec<ManagedUser>> {
        let mut connection = self.pool.acquire().await?;
        let account_query =
            format!("SELECT {ACCOUNT_SELECT} FROM web_accounts ORDER BY login_name COLLATE BINARY");
        let accounts = sqlx::query(&account_query)
            .fetch_all(&mut *connection)
            .await?
            .into_iter()
            .map(row_to_account)
            .collect::<Result<Vec<_>>>()?;
        let mut users = Vec::with_capacity(accounts.len());
        for account in accounts {
            users.push(fetch_managed_for_account(&mut connection, account).await?);
        }

        let legacy_query = format!(
            "SELECT {USER_SELECT} FROM users u \
             WHERE NOT EXISTS (\
                 SELECT 1 FROM web_accounts a WHERE a.linked_username = u.username\
             ) ORDER BY u.username COLLATE BINARY"
        );
        let profiles = sqlx::query(&legacy_query)
            .fetch_all(&mut *connection)
            .await?
            .into_iter()
            .map(row_to_user)
            .collect::<Result<Vec<_>>>()?;
        for profile in profiles {
            let has_private_key: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM user_private_keys WHERE username = ?)",
            )
            .bind(&profile.username)
            .fetch_one(&mut *connection)
            .await?;
            users.push(ManagedUser {
                account: None,
                profile: Some(profile),
                has_private_key,
                providers: Vec::new(),
            });
        }
        Ok(users)
    }

    async fn get_managed_user(&self, account_id: &str) -> Result<Option<ManagedUser>> {
        let account_id = normalize_account_id(account_id)?;
        let mut connection = self.pool.acquire().await?;
        let Some(account) = fetch_account_by_id(&mut connection, &account_id).await? else {
            return Ok(None);
        };
        fetch_managed_for_account(&mut connection, account)
            .await
            .map(Some)
    }

    async fn get_managed_user_by_username(&self, username: &str) -> Result<Option<ManagedUser>> {
        let username = normalize_username(username)?;
        let mut connection = self.pool.acquire().await?;
        let Some(profile) = fetch_profile(&mut connection, &username).await? else {
            return Ok(None);
        };
        let account_query =
            format!("SELECT {ACCOUNT_SELECT} FROM web_accounts WHERE linked_username = ?");
        let account = sqlx::query(&account_query)
            .bind(&username)
            .fetch_optional(&mut *connection)
            .await?
            .map(row_to_account)
            .transpose()?;
        if let Some(account) = account {
            fetch_managed_for_account(&mut connection, account)
                .await
                .map(Some)
        } else {
            let has_private_key: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM user_private_keys WHERE username = ?)",
            )
            .bind(&username)
            .fetch_one(&mut *connection)
            .await?;
            Ok(Some(ManagedUser {
                account: None,
                profile: Some(profile),
                has_private_key,
                providers: Vec::new(),
            }))
        }
    }

    #[instrument(
        skip(self, user),
        fields(account_id = %user.account_id, login_name = %user.login_name)
    )]
    async fn create_managed_user(&self, user: NewManagedUser) -> Result<ManagedUser> {
        let NewManagedUser {
            account_id,
            login_name,
            password_hash,
            role,
            status,
            display_name,
            email,
            avatar_url,
            profile,
            encrypted_private_key,
            external_identity,
        } = user;
        let account_id = normalize_account_id(&account_id)?;
        let login_name = normalize_username(&login_name)?;
        let password_hash = normalize_password_hash(password_hash)?;
        let display_name =
            normalize_optional_field("display_name", display_name, MAX_DISPLAY_NAME_BYTES)?;
        let email = normalize_optional_field("email", email, MAX_EMAIL_BYTES)?;
        let avatar_url = normalize_optional_field("avatar_url", avatar_url, MAX_AVATAR_URL_BYTES)?;
        let profile = normalize_new_user(profile)?;
        validate_private_key_envelope(&encrypted_private_key)?;
        let external_identity = external_identity
            .map(normalize_external_identity)
            .transpose()?;

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if role == AccountRole::User {
            ensure_user_account_capacity(&mut transaction, self.max_user_accounts).await?;
        }
        ensure_account_identifiers_available(
            &mut transaction,
            &account_id,
            &login_name,
            Some(&profile.username),
        )
        .await?;
        if let Some(identity) = &external_identity {
            ensure_external_identity_available(&mut transaction, identity).await?;
        }

        let timestamp = now();
        insert_profile(&mut transaction, &profile, timestamp).await?;
        sqlx::query(
            "INSERT INTO web_accounts \
             (account_id, login_name, password_hash, role, status, linked_username, \
              display_name, email, avatar_url, auth_version, last_login_at, \
              created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?, ?)",
        )
        .bind(&account_id)
        .bind(&login_name)
        .bind(password_hash)
        .bind(role.as_str())
        .bind(status.as_str())
        .bind(&profile.username)
        .bind(&display_name)
        .bind(&email)
        .bind(&avatar_url)
        .bind(timestamp)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO user_private_keys \
             (username, encrypted_private_key, key_version, updated_at) VALUES (?, ?, 1, ?)",
        )
        .bind(&profile.username)
        .bind(&encrypted_private_key)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
        if let Some(identity) = &external_identity {
            sqlx::query(
                "INSERT INTO external_identities (provider, subject, account_id) VALUES (?, ?, ?)",
            )
            .bind(&identity.provider)
            .bind(&identity.subject)
            .bind(&account_id)
            .execute(&mut *transaction)
            .await?;
        }

        let account = fetch_account_by_id(&mut transaction, &account_id)
            .await?
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema("刚创建的 web_accounts 记录不可见".to_string())
            })?;
        let managed = fetch_managed_for_account(&mut transaction, account).await?;
        transaction.commit().await?;
        info!(
            account_id,
            username = profile.username,
            "托管用户已原子创建"
        );
        Ok(managed)
    }

    #[instrument(
        skip(self, account),
        fields(account_id = %account.account_id, login_name = %account.login_name)
    )]
    async fn create_user_account(&self, account: NewUserAccount) -> Result<WebAccount> {
        let NewUserAccount {
            account_id,
            login_name,
            password_hash,
            display_name,
            email,
            avatar_url,
            external_identity,
        } = account;
        let account_id = normalize_account_id(&account_id)?;
        let login_name = normalize_username(&login_name)?;
        let password_hash = normalize_password_hash(password_hash)?;
        let display_name =
            normalize_optional_field("display_name", display_name, MAX_DISPLAY_NAME_BYTES)?;
        let email = normalize_optional_field("email", email, MAX_EMAIL_BYTES)?;
        let avatar_url = normalize_optional_field("avatar_url", avatar_url, MAX_AVATAR_URL_BYTES)?;
        let external_identity = external_identity
            .map(normalize_external_identity)
            .transpose()?;

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        ensure_user_account_capacity(&mut transaction, self.max_user_accounts).await?;
        // 初始密钥审批会把 login_name 直接作为 Proxy username。注册阶段就在同一
        // 写事务中保留该名字，避免 legacy/direct profile 使审批永久冲突。
        ensure_account_identifiers_available(
            &mut transaction,
            &account_id,
            &login_name,
            Some(&login_name),
        )
        .await?;
        if let Some(identity) = &external_identity {
            ensure_external_identity_available(&mut transaction, identity).await?;
        }

        let timestamp = now();
        sqlx::query(
            "INSERT INTO web_accounts \
             (account_id, login_name, password_hash, role, status, linked_username, \
              display_name, email, avatar_url, auth_version, last_login_at, \
              created_at, updated_at) \
             VALUES (?, ?, ?, 'user', 'active', NULL, ?, ?, ?, 1, NULL, ?, ?)",
        )
        .bind(&account_id)
        .bind(&login_name)
        .bind(password_hash)
        .bind(&display_name)
        .bind(&email)
        .bind(&avatar_url)
        .bind(timestamp)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
        if let Some(identity) = &external_identity {
            sqlx::query(
                "INSERT INTO external_identities (provider, subject, account_id) VALUES (?, ?, ?)",
            )
            .bind(&identity.provider)
            .bind(&identity.subject)
            .bind(&account_id)
            .execute(&mut *transaction)
            .await?;
        }
        let account = fetch_account_by_id(&mut transaction, &account_id)
            .await?
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema(
                    "刚创建的普通 web_accounts 记录不可见".to_string(),
                )
            })?;
        transaction.commit().await?;
        info!(account_id, "无 Proxy profile 的普通 Web 账号已创建");
        Ok(account)
    }

    #[instrument(skip(self, update), fields(account_id))]
    async fn update_managed_user(
        &self,
        account_id: &str,
        update: ManagedUserUpdate,
    ) -> Result<ManagedUser> {
        let account_id = normalize_account_id(account_id)?;
        if update.is_empty() {
            return Err(ValidationError::EmptyUpdate.into());
        }
        let permissions = update
            .permissions
            .as_deref()
            .map(normalize_permissions)
            .transpose()?;
        let display_name = update
            .display_name
            .map(|value| {
                value
                    .map(|value| normalize_field("display_name", &value, MAX_DISPLAY_NAME_BYTES))
                    .transpose()
            })
            .transpose()?;
        let email = update
            .email
            .map(|value| {
                value
                    .map(|value| normalize_field("email", &value, MAX_EMAIL_BYTES))
                    .transpose()
            })
            .transpose()?;
        let avatar_url = update
            .avatar_url
            .map(|value| {
                value
                    .map(|value| normalize_field("avatar_url", &value, MAX_AVATAR_URL_BYTES))
                    .transpose()
            })
            .transpose()?;

        let profile_update_requested =
            update.enabled.is_some() || permissions.is_some() || update.expires_at.is_some();
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let Some(mut account) = fetch_account_by_id(&mut transaction, &account_id).await? else {
            return Err(UserRepositoryError::NotFound(account_id));
        };
        let target_role = update.role.unwrap_or(account.role);
        let target_status = update.status.unwrap_or(account.status);
        guard_last_admin(
            &mut transaction,
            &account,
            Some(target_role),
            Some(target_status),
        )
        .await?;

        let mut profile = match account.linked_username.as_deref() {
            Some(username) => fetch_profile(&mut transaction, username).await?,
            None => None,
        };
        if profile_update_requested && profile.is_none() {
            return Err(UserRepositoryError::NotFound(format!(
                "账号 {} 未关联 Proxy 用户",
                account.account_id
            )));
        }

        let auth_changed = account.role != target_role || account.status != target_status;
        account.role = target_role;
        account.status = target_status;
        if let Some(display_name) = display_name {
            account.display_name = display_name;
        }
        if let Some(email) = email {
            account.email = email;
        }
        if let Some(avatar_url) = avatar_url {
            account.avatar_url = avatar_url;
        }
        if auth_changed {
            account.auth_version = account.auth_version.checked_add(1).ok_or_else(|| {
                UserRepositoryError::InvalidSchema(format!(
                    "账号 {} 的 auth_version 已溢出",
                    account.account_id
                ))
            })?;
        }
        account.updated_at = now();
        sqlx::query(
            "UPDATE web_accounts SET role = ?, status = ?, display_name = ?, email = ?, \
             avatar_url = ?, auth_version = ?, updated_at = ? WHERE account_id = ?",
        )
        .bind(account.role.as_str())
        .bind(account.status.as_str())
        .bind(&account.display_name)
        .bind(&account.email)
        .bind(&account.avatar_url)
        .bind(account.auth_version)
        .bind(account.updated_at)
        .bind(&account.account_id)
        .execute(&mut *transaction)
        .await?;

        if let Some(profile) = profile.as_mut() {
            if let Some(enabled) = update.enabled {
                profile.enabled = enabled;
            }
            if let Some(permissions) = permissions {
                profile.permissions = permissions;
            }
            if let Some(expires_at) = update.expires_at {
                profile.expires_at = expires_at;
            }
            if profile_update_requested {
                profile.updated_at = now();
                sqlx::query(
                    "UPDATE users SET permissions = ?, enabled = ?, expires_at = ?, \
                     updated_at = ? WHERE username = ?",
                )
                .bind(encode_permissions(&profile.permissions))
                .bind(profile.enabled)
                .bind(profile.expires_at)
                .bind(profile.updated_at)
                .bind(&profile.username)
                .execute(&mut *transaction)
                .await?;
            }
        }

        let managed = fetch_managed_for_account(&mut transaction, account).await?;
        transaction.commit().await?;
        info!(account_id, "托管用户配置已更新");
        Ok(managed)
    }

    async fn update_last_login(&self, account_id: &str, logged_in_at: i64) -> Result<()> {
        let account_id = normalize_account_id(account_id)?;
        let result = sqlx::query(
            "UPDATE web_accounts SET last_login_at = ?, updated_at = ? WHERE account_id = ?",
        )
        .bind(logged_in_at)
        .bind(now())
        .bind(&account_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(account_id));
        }
        Ok(())
    }

    async fn load_encrypted_private_key(
        &self,
        username: &str,
    ) -> Result<Option<EncryptedPrivateKey>> {
        let username = normalize_username(username)?;
        sqlx::query(
            "SELECT username, encrypted_private_key, key_version, updated_at \
             FROM user_private_keys WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?
        .map(row_to_encrypted_private_key)
        .transpose()
    }

    #[instrument(skip(self, rotation), fields(username = %rotation.username))]
    async fn rotate_keypair(&self, rotation: KeyPairRotation) -> Result<UserRecord> {
        let username = normalize_username(&rotation.username)?;
        let public_key_pem = normalize_public_key_pem(&rotation.public_key_pem)?;
        validate_private_key_envelope(&rotation.encrypted_private_key)?;
        if rotation.expected_key_version < 1 {
            return Err(ValidationError::InvalidAccountField(
                "expected_key_version 必须大于等于 1".to_string(),
            )
            .into());
        }

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let actual: Option<i64> =
            sqlx::query_scalar("SELECT key_version FROM users WHERE username = ?")
                .bind(&username)
                .fetch_optional(&mut *transaction)
                .await?;
        let Some(actual) = actual else {
            return Err(UserRepositoryError::NotFound(username));
        };
        if actual != rotation.expected_key_version {
            return Err(UserRepositoryError::VersionConflict {
                username,
                expected: rotation.expected_key_version,
                actual,
            });
        }
        let new_version = actual.checked_add(1).ok_or_else(|| {
            UserRepositoryError::InvalidSchema("用户 key_version 已溢出".to_string())
        })?;
        let timestamp = now();
        let query = format!(
            "UPDATE users SET public_key_pem = ?, key_version = ?, updated_at = ? \
             WHERE username = ? AND key_version = ? RETURNING {USER_SELECT}"
        );
        let user = sqlx::query(&query)
            .bind(public_key_pem)
            .bind(new_version)
            .bind(timestamp)
            .bind(&username)
            .bind(actual)
            .fetch_optional(&mut *transaction)
            .await?
            .map(row_to_user)
            .transpose()?
            .ok_or_else(|| UserRepositoryError::VersionConflict {
                username: username.clone(),
                expected: rotation.expected_key_version,
                actual,
            })?;

        // UPSERT 是有意的：历史 legacy 用户可能没有私钥记录，也应能轮换。
        sqlx::query(
            "INSERT INTO user_private_keys \
             (username, encrypted_private_key, key_version, updated_at) VALUES (?, ?, ?, ?) \
             ON CONFLICT(username) DO UPDATE SET \
                 encrypted_private_key = excluded.encrypted_private_key, \
                 key_version = excluded.key_version, \
                 updated_at = excluded.updated_at",
        )
        .bind(&username)
        .bind(rotation.encrypted_private_key)
        .bind(new_version)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        info!(username, key_version = new_version, "用户密钥对已轮换");
        Ok(user)
    }

    #[instrument(
        skip(self, request),
        fields(request_id = %request.request_id, account_id = %request.account_id)
    )]
    async fn submit_key_generation_request(
        &self,
        request: NewKeyGenerationRequest,
    ) -> Result<KeyGenerationRequest> {
        let request_id = normalize_request_id(&request.request_id)?;
        let account_id = normalize_account_id(&request.account_id)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let account = fetch_account_by_id(&mut transaction, &account_id)
            .await?
            .ok_or_else(|| UserRepositoryError::NotFound(account_id.clone()))?;
        ensure_active_normal_account(&account)?;

        if let Some(existing) =
            fetch_pending_key_request_for_account(&mut transaction, &account_id).await?
        {
            return Err(UserRepositoryError::PendingKeyRequestConflict {
                account_id,
                request_id: existing.request_id,
            });
        }

        let timestamp = now();
        let (kind, expected_key_version) = match account.linked_username.as_deref() {
            None => (KeyRequestKind::Initial, None),
            Some(username) => {
                let profile = fetch_profile(&mut transaction, username)
                    .await?
                    .ok_or_else(|| {
                        UserRepositoryError::InvalidSchema(format!(
                            "账号 {} 关联的用户 {username} 不存在",
                            account.account_id
                        ))
                    })?;
                if !profile.enabled {
                    return Err(UserRepositoryError::KeyRequestNotEligible {
                        account_id,
                        reason: "Proxy 用户已停用".to_string(),
                    });
                }
                let has_private_key: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM user_private_keys WHERE username = ?)",
                )
                .bind(username)
                .fetch_one(&mut *transaction)
                .await?;
                let expired = profile
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= timestamp);
                if has_private_key && !expired {
                    return Err(UserRepositoryError::KeyRequestNotEligible {
                        account_id,
                        reason: "现有密钥仍有效".to_string(),
                    });
                }
                (KeyRequestKind::Rotate, Some(profile.key_version))
            }
        };

        sqlx::query(
            "INSERT INTO key_generation_requests \
             (request_id, account_id, kind, status, expected_key_version, \
              reviewer_account_id, requested_at, reviewed_at, approved_expires_at) \
             VALUES (?, ?, ?, 'pending', ?, NULL, ?, NULL, NULL)",
        )
        .bind(&request_id)
        .bind(&account.account_id)
        .bind(kind.as_str())
        .bind(expected_key_version)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
        let request = fetch_key_request_by_id(&mut transaction, &request_id)
            .await?
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema(
                    "刚创建的 key_generation_requests 记录不可见".to_string(),
                )
            })?;
        transaction.commit().await?;
        info!(
            request_id,
            account_id = account.account_id,
            kind = kind.as_str(),
            "用户已提交密钥申请"
        );
        Ok(request)
    }

    async fn get_pending_key_generation_request(
        &self,
        account_id: &str,
    ) -> Result<Option<KeyGenerationRequest>> {
        let account_id = normalize_account_id(account_id)?;
        let mut connection = self.pool.acquire().await?;
        fetch_pending_key_request_for_account(&mut connection, &account_id).await
    }

    async fn get_key_generation_request(
        &self,
        request_id: &str,
    ) -> Result<Option<KeyGenerationRequest>> {
        let request_id = normalize_request_id(request_id)?;
        let mut connection = self.pool.acquire().await?;
        fetch_key_request_by_id(&mut connection, &request_id).await
    }

    async fn list_pending_key_generation_requests(&self) -> Result<Vec<KeyGenerationRequest>> {
        let query = format!(
            "SELECT {KEY_REQUEST_SELECT} FROM key_generation_requests \
             WHERE status = 'pending' ORDER BY requested_at, request_id COLLATE BINARY"
        );
        sqlx::query(&query)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(row_to_key_request)
            .collect()
    }

    #[instrument(
        skip(self, approval),
        fields(
            request_id = %approval.request_id,
            reviewer_account_id = %approval.reviewer_account_id
        )
    )]
    async fn approve_key_generation_request(
        &self,
        approval: KeyRequestApproval,
    ) -> Result<KeyRequestApprovalResult> {
        let KeyRequestApproval {
            request_id,
            reviewer_account_id,
            expires_at,
            material,
        } = approval;
        let request_id = normalize_request_id(&request_id)?;
        let reviewer_account_id = normalize_account_id(&reviewer_account_id)?;

        let material = match material {
            ApprovedKeyMaterial::Initial {
                mut profile,
                encrypted_private_key,
            } => {
                profile.expires_at = Some(expires_at);
                let profile = normalize_new_user(profile)?;
                validate_private_key_envelope(&encrypted_private_key)?;
                ApprovedKeyMaterial::Initial {
                    profile,
                    encrypted_private_key,
                }
            }
            ApprovedKeyMaterial::Rotate {
                public_key_pem,
                encrypted_private_key,
            } => {
                let public_key_pem = normalize_public_key_pem(&public_key_pem)?;
                validate_private_key_envelope(&encrypted_private_key)?;
                ApprovedKeyMaterial::Rotate {
                    public_key_pem,
                    encrypted_private_key,
                }
            }
        };

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        // 必须在取得写锁后判断，避免等待锁期间过期时间已经越过当前时刻。
        let timestamp = now();
        if expires_at <= timestamp {
            return Err(UserRepositoryError::InvalidApprovalExpiration {
                expires_at,
                now: timestamp,
            });
        }
        let request = fetch_key_request_by_id(&mut transaction, &request_id)
            .await?
            .ok_or_else(|| UserRepositoryError::KeyRequestNotFound(request_id.clone()))?;
        if request.status != KeyRequestStatus::Pending {
            return Err(UserRepositoryError::KeyRequestAlreadyReviewed {
                request_id,
                status: request.status,
            });
        }
        let reviewer = fetch_account_by_id(&mut transaction, &reviewer_account_id)
            .await?
            .ok_or_else(|| UserRepositoryError::NotFound(reviewer_account_id.clone()))?;
        ensure_active_admin(&reviewer)?;
        let mut account = fetch_account_by_id(&mut transaction, &request.account_id)
            .await?
            .ok_or_else(|| UserRepositoryError::NotFound(request.account_id.clone()))?;
        ensure_active_normal_account(&account)?;

        match (request.kind, material) {
            (
                KeyRequestKind::Initial,
                ApprovedKeyMaterial::Initial {
                    profile,
                    encrypted_private_key,
                },
            ) => {
                if account.linked_username.is_some() {
                    return Err(UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: "账号已经关联 Proxy 用户".to_string(),
                    });
                }
                if !profile.enabled {
                    return Err(UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: "初始审批不能创建停用的 Proxy 用户".to_string(),
                    });
                }
                let profile_exists: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)")
                        .bind(&profile.username)
                        .fetch_one(&mut *transaction)
                        .await?;
                if profile_exists {
                    return Err(UserRepositoryError::Conflict(profile.username));
                }
                insert_profile(&mut transaction, &profile, timestamp).await?;
                sqlx::query(
                    "UPDATE web_accounts SET linked_username = ?, updated_at = ? \
                     WHERE account_id = ? AND linked_username IS NULL",
                )
                .bind(&profile.username)
                .bind(timestamp)
                .bind(&account.account_id)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "INSERT INTO user_private_keys \
                     (username, encrypted_private_key, key_version, updated_at) \
                     VALUES (?, ?, 1, ?)",
                )
                .bind(&profile.username)
                .bind(encrypted_private_key)
                .bind(timestamp)
                .execute(&mut *transaction)
                .await?;
                account.linked_username = Some(profile.username);
                account.updated_at = timestamp;
            }
            (
                KeyRequestKind::Rotate,
                ApprovedKeyMaterial::Rotate {
                    public_key_pem,
                    encrypted_private_key,
                },
            ) => {
                let username = account.linked_username.as_deref().ok_or_else(|| {
                    UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: "账号不再关联 Proxy 用户".to_string(),
                    }
                })?;
                let profile = fetch_profile(&mut transaction, username)
                    .await?
                    .ok_or_else(|| {
                        UserRepositoryError::InvalidSchema(format!(
                            "账号 {} 关联的用户 {username} 不存在",
                            account.account_id
                        ))
                    })?;
                if !profile.enabled {
                    return Err(UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: "Proxy 用户已在申请后被停用".to_string(),
                    });
                }
                let expected = request.expected_key_version.ok_or_else(|| {
                    UserRepositoryError::InvalidSchema(format!(
                        "轮换申请 {} 缺少 expected_key_version",
                        request.request_id
                    ))
                })?;
                if profile.key_version != expected {
                    return Err(UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: format!(
                            "密钥版本已变化，期望 {expected}，实际 {}",
                            profile.key_version
                        ),
                    });
                }
                let new_version = expected.checked_add(1).ok_or_else(|| {
                    UserRepositoryError::InvalidSchema(format!(
                        "用户 {username} 的 key_version 已溢出"
                    ))
                })?;
                let result = sqlx::query(
                    "UPDATE users SET public_key_pem = ?, key_version = ?, expires_at = ?, \
                     updated_at = ? WHERE username = ? AND key_version = ?",
                )
                .bind(public_key_pem)
                .bind(new_version)
                .bind(expires_at)
                .bind(timestamp)
                .bind(username)
                .bind(expected)
                .execute(&mut *transaction)
                .await?;
                if result.rows_affected() != 1 {
                    return Err(UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: "密钥版本在审批期间发生变化".to_string(),
                    });
                }
                sqlx::query(
                    "INSERT INTO user_private_keys \
                     (username, encrypted_private_key, key_version, updated_at) VALUES (?, ?, ?, ?) \
                     ON CONFLICT(username) DO UPDATE SET \
                         encrypted_private_key = excluded.encrypted_private_key, \
                         key_version = excluded.key_version, \
                         updated_at = excluded.updated_at",
                )
                .bind(username)
                .bind(encrypted_private_key)
                .bind(new_version)
                .bind(timestamp)
                .execute(&mut *transaction)
                .await?;
            }
            (kind, _) => {
                return Err(UserRepositoryError::StaleKeyRequest {
                    request_id: request.request_id.clone(),
                    reason: format!("审批材料与 {} 申请不匹配", kind.as_str()),
                });
            }
        }

        let result = sqlx::query(
            "UPDATE key_generation_requests SET status = 'approved', \
             reviewer_account_id = ?, reviewed_at = ?, approved_expires_at = ? \
             WHERE request_id = ? AND status = 'pending'",
        )
        .bind(&reviewer.account_id)
        .bind(timestamp)
        .bind(expires_at)
        .bind(&request.request_id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(UserRepositoryError::KeyRequestAlreadyReviewed {
                request_id: request.request_id,
                status: KeyRequestStatus::Pending,
            });
        }
        let request = fetch_key_request_by_id(&mut transaction, &request_id)
            .await?
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema(
                    "刚批准的 key_generation_requests 记录不可见".to_string(),
                )
            })?;
        let managed_user = fetch_managed_for_account(&mut transaction, account).await?;
        transaction.commit().await?;
        info!(
            request_id,
            reviewer_account_id,
            account_id = request.account_id,
            kind = request.kind.as_str(),
            "管理员已批准密钥申请"
        );
        Ok(KeyRequestApprovalResult {
            request,
            managed_user,
        })
    }

    #[instrument(skip(self), fields(request_id, reviewer_account_id))]
    async fn reject_key_generation_request(
        &self,
        request_id: &str,
        reviewer_account_id: &str,
    ) -> Result<KeyGenerationRequest> {
        let request_id = normalize_request_id(request_id)?;
        let reviewer_account_id = normalize_account_id(reviewer_account_id)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let request = fetch_key_request_by_id(&mut transaction, &request_id)
            .await?
            .ok_or_else(|| UserRepositoryError::KeyRequestNotFound(request_id.clone()))?;
        if request.status != KeyRequestStatus::Pending {
            return Err(UserRepositoryError::KeyRequestAlreadyReviewed {
                request_id,
                status: request.status,
            });
        }
        let reviewer = fetch_account_by_id(&mut transaction, &reviewer_account_id)
            .await?
            .ok_or_else(|| UserRepositoryError::NotFound(reviewer_account_id.clone()))?;
        ensure_active_admin(&reviewer)?;
        let timestamp = now();
        let result = sqlx::query(
            "UPDATE key_generation_requests SET status = 'rejected', \
             reviewer_account_id = ?, reviewed_at = ? \
             WHERE request_id = ? AND status = 'pending'",
        )
        .bind(&reviewer.account_id)
        .bind(timestamp)
        .bind(&request.request_id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(UserRepositoryError::KeyRequestAlreadyReviewed {
                request_id: request.request_id,
                status: KeyRequestStatus::Pending,
            });
        }
        let request = fetch_key_request_by_id(&mut transaction, &request_id)
            .await?
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema(
                    "刚拒绝的 key_generation_requests 记录不可见".to_string(),
                )
            })?;
        transaction.commit().await?;
        info!(
            request_id,
            reviewer_account_id,
            account_id = request.account_id,
            kind = request.kind.as_str(),
            "管理员已拒绝密钥申请"
        );
        Ok(request)
    }

    #[instrument(skip(self), fields(account_id))]
    async fn delete_managed_user(&self, account_id: &str) -> Result<()> {
        let account_id = normalize_account_id(account_id)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let Some(account) = fetch_account_by_id(&mut transaction, &account_id).await? else {
            return Err(UserRepositoryError::NotFound(account_id));
        };
        guard_last_admin(&mut transaction, &account, None, None).await?;

        sqlx::query("DELETE FROM web_accounts WHERE account_id = ?")
            .bind(&account.account_id)
            .execute(&mut *transaction)
            .await?;
        if let Some(username) = &account.linked_username {
            sqlx::query("DELETE FROM users WHERE username = ?")
                .bind(username)
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        info!(account_id, "托管用户已删除");
        Ok(())
    }

    async fn active_admin_count(&self) -> Result<u64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM web_accounts WHERE role = 'admin' AND status = 'active'",
        )
        .fetch_one(&self.pool)
        .await?;
        u64::try_from(count)
            .map_err(|_| UserRepositoryError::InvalidSchema("管理员数量不能表示为 u64".to_string()))
    }
}

async fn migrate_users_table(
    transaction: &mut Transaction<'_, Sqlite>,
    schema_version: i64,
) -> Result<()> {
    let users_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'users')",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !users_exists {
        if schema_version != 0 {
            return Err(UserRepositoryError::InvalidSchema(
                "users 表不存在".to_string(),
            ));
        }
        sqlx::query(
            r#"
            CREATE TABLE users (
                username TEXT COLLATE BINARY NOT NULL PRIMARY KEY,
                public_key_pem TEXT NOT NULL CHECK (
                    length(public_key_pem) > 0 AND length(public_key_pem) <= 16384
                ),
                permissions TEXT NOT NULL DEFAULT 'proxy.connect.tcp,proxy.connect.udp',
                enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                origin TEXT NOT NULL DEFAULT 'legacy'
                    CHECK(origin IN ('local', 'google', 'wechat', 'admin', 'legacy')),
                key_version INTEGER NOT NULL DEFAULT 1 CHECK(key_version >= 1),
                expires_at INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }

    let columns = table_columns(transaction, "users").await?;
    for required in ["username", "public_key_pem", "created_at", "updated_at"] {
        if !columns.iter().any(|column| column == required) {
            return Err(UserRepositoryError::InvalidSchema(format!(
                "users 表缺少字段 {required}"
            )));
        }
    }
    if !columns.iter().any(|column| column == "expires_at") {
        sqlx::query("ALTER TABLE users ADD COLUMN expires_at INTEGER")
            .execute(&mut **transaction)
            .await?;
    }
    if !columns.iter().any(|column| column == "permissions") {
        sqlx::query(
            "ALTER TABLE users ADD COLUMN permissions TEXT NOT NULL \
             DEFAULT 'proxy.connect.tcp,proxy.connect.udp'",
        )
        .execute(&mut **transaction)
        .await?;
    }
    if !columns.iter().any(|column| column == "enabled") {
        sqlx::query(
            "ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1 \
             CHECK(enabled IN (0, 1))",
        )
        .execute(&mut **transaction)
        .await?;
    }
    if !columns.iter().any(|column| column == "origin") {
        sqlx::query(
            "ALTER TABLE users ADD COLUMN origin TEXT NOT NULL DEFAULT 'legacy' \
             CHECK(origin IN ('local', 'google', 'wechat', 'admin', 'legacy'))",
        )
        .execute(&mut **transaction)
        .await?;
    }
    if !columns.iter().any(|column| column == "key_version") {
        sqlx::query(
            "ALTER TABLE users ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1 \
             CHECK(key_version >= 1)",
        )
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn create_v2_tables(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    // v1 不应包含这些表。故意不使用 IF NOT EXISTS，以免将半成品 schema 盖章为 v2。
    sqlx::query(
        r#"
        CREATE TABLE web_accounts (
            account_id TEXT COLLATE BINARY NOT NULL PRIMARY KEY,
            login_name TEXT COLLATE BINARY NOT NULL UNIQUE,
            password_hash TEXT,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
            linked_username TEXT COLLATE BINARY UNIQUE,
            display_name TEXT,
            email TEXT,
            avatar_url TEXT,
            auth_version INTEGER NOT NULL DEFAULT 1 CHECK(auth_version >= 1),
            last_login_at INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(linked_username) REFERENCES users(username)
                ON UPDATE CASCADE ON DELETE RESTRICT
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE external_identities (
            provider TEXT NOT NULL,
            subject TEXT NOT NULL,
            account_id TEXT COLLATE BINARY NOT NULL,
            PRIMARY KEY(provider, subject),
            FOREIGN KEY(account_id) REFERENCES web_accounts(account_id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE user_private_keys (
            username TEXT COLLATE BINARY NOT NULL PRIMARY KEY,
            encrypted_private_key BLOB NOT NULL CHECK(length(encrypted_private_key) > 0),
            key_version INTEGER NOT NULL CHECK(key_version >= 1),
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
                ON UPDATE CASCADE ON DELETE CASCADE
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_web_accounts_active_admin ON web_accounts(role, status) \
         WHERE role = 'admin' AND status = 'active'",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query("CREATE INDEX idx_external_identities_account ON external_identities(account_id)")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn create_v3_tables(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    // v2 不应包含这些表。故意不使用 IF NOT EXISTS，避免把不完整的手工 schema
    // 误判成成功迁移。
    sqlx::query(
        r#"
        CREATE TABLE key_generation_requests (
            request_id TEXT COLLATE BINARY NOT NULL PRIMARY KEY,
            account_id TEXT COLLATE BINARY NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('initial', 'rotate')),
            status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
            expected_key_version INTEGER CHECK(expected_key_version IS NULL OR expected_key_version >= 1),
            reviewer_account_id TEXT COLLATE BINARY,
            requested_at INTEGER NOT NULL,
            reviewed_at INTEGER,
            approved_expires_at INTEGER,
            FOREIGN KEY(account_id) REFERENCES web_accounts(account_id) ON DELETE CASCADE,
            CHECK (
                (kind = 'initial' AND expected_key_version IS NULL) OR
                (kind = 'rotate' AND expected_key_version IS NOT NULL)
            ),
            CHECK (
                (status = 'pending' AND reviewer_account_id IS NULL
                    AND reviewed_at IS NULL AND approved_expires_at IS NULL) OR
                (status = 'approved' AND reviewer_account_id IS NOT NULL
                    AND reviewed_at IS NOT NULL AND approved_expires_at IS NOT NULL) OR
                (status = 'rejected' AND reviewer_account_id IS NOT NULL
                    AND reviewed_at IS NOT NULL AND approved_expires_at IS NULL)
            )
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX idx_key_requests_one_pending_per_account \
         ON key_generation_requests(account_id) WHERE status = 'pending'",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_key_requests_pending_order \
         ON key_generation_requests(status, requested_at, request_id)",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE user_access_records (
            record_id INTEGER NOT NULL PRIMARY KEY,
            username TEXT COLLATE BINARY NOT NULL,
            protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
            target_host TEXT NOT NULL CHECK(length(target_host) > 0 AND length(target_host) <= 1024),
            target_port INTEGER NOT NULL CHECK(target_port BETWEEN 1 AND 65535),
            accessed_at INTEGER NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
                ON UPDATE CASCADE ON DELETE CASCADE
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_access_records_user_time \
         ON user_access_records(username, accessed_at DESC, record_id DESC)",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query("CREATE INDEX idx_access_records_time ON user_access_records(accessed_at)")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "INSERT INTO app_metadata (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO NOTHING",
    )
    .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
    .bind(DEFAULT_ACCESS_LOG_RETENTION_DAYS.to_string())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn migrate_access_records_to_v4(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE user_access_records_v4 (
            record_id INTEGER NOT NULL PRIMARY KEY,
            username TEXT COLLATE BINARY NOT NULL,
            protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
            target_host TEXT COLLATE NOCASE NOT NULL
                CHECK(length(target_host) > 0 AND length(target_host) <= 1024),
            target_port INTEGER NOT NULL CHECK(target_port BETWEEN 1 AND 65535),
            access_count INTEGER NOT NULL CHECK(access_count >= 1),
            accessed_at INTEGER NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
                ON UPDATE CASCADE ON DELETE CASCADE,
            UNIQUE(username, target_host)
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        WITH normalized AS (
            SELECT
                record_id,
                username,
                protocol,
                lower(target_host) AS target_host,
                target_port,
                accessed_at
            FROM user_access_records
        ),
        ranked AS (
            SELECT
                record_id,
                username,
                protocol,
                target_host,
                target_port,
                COUNT(*) OVER (
                    PARTITION BY username, target_host
                ) AS access_count,
                accessed_at,
                ROW_NUMBER() OVER (
                    PARTITION BY username, target_host
                    ORDER BY accessed_at DESC, record_id DESC
                ) AS recency_rank
            FROM normalized
        )
        INSERT INTO user_access_records_v4 (
            record_id,
            username,
            protocol,
            target_host,
            target_port,
            access_count,
            accessed_at
        )
        SELECT
            record_id,
            username,
            protocol,
            target_host,
            target_port,
            access_count,
            accessed_at
        FROM ranked
        WHERE recency_rank = 1
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query("DROP TABLE user_access_records")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("ALTER TABLE user_access_records_v4 RENAME TO user_access_records")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "CREATE INDEX idx_access_records_user_time \
         ON user_access_records(username, accessed_at DESC, record_id DESC)",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query("CREATE INDEX idx_access_records_time ON user_access_records(accessed_at)")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn create_v5_tables(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE agent_device_authorizations (
            device_code_hash TEXT COLLATE BINARY NOT NULL PRIMARY KEY
                CHECK(length(device_code_hash) = 43),
            user_code_hash TEXT COLLATE BINARY NOT NULL UNIQUE
                CHECK(length(user_code_hash) = 43),
            client_name TEXT NOT NULL
                CHECK(length(client_name) > 0 AND length(client_name) <= 128),
            platform TEXT NOT NULL
                CHECK(length(platform) > 0 AND length(platform) <= 32),
            status TEXT NOT NULL
                CHECK(status IN ('pending', 'authorized', 'denied', 'consumed')),
            authorized_account_id TEXT COLLATE BINARY,
            authorized_auth_version INTEGER
                CHECK(authorized_auth_version IS NULL OR authorized_auth_version >= 1),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
            authorized_at INTEGER,
            consumed_at INTEGER,
            last_polled_at INTEGER,
            FOREIGN KEY(authorized_account_id) REFERENCES web_accounts(account_id)
                ON DELETE CASCADE,
            CHECK (
                (status = 'pending' AND authorized_account_id IS NULL
                    AND authorized_auth_version IS NULL AND authorized_at IS NULL
                    AND consumed_at IS NULL) OR
                (status = 'authorized' AND authorized_account_id IS NOT NULL
                    AND authorized_auth_version IS NOT NULL AND authorized_at IS NOT NULL
                    AND consumed_at IS NULL) OR
                (status = 'denied' AND authorized_account_id IS NOT NULL
                    AND authorized_auth_version IS NULL AND authorized_at IS NOT NULL
                    AND consumed_at IS NULL) OR
                (status = 'consumed' AND authorized_account_id IS NOT NULL
                    AND authorized_auth_version IS NOT NULL AND authorized_at IS NOT NULL
                    AND consumed_at IS NOT NULL)
            )
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_agent_device_authorizations_expiry \
         ON agent_device_authorizations(expires_at)",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn ensure_v5_indexes(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_web_accounts_role \
         ON web_accounts(role)",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_agent_device_authorizations_active_expiry \
         ON agent_device_authorizations(expires_at) \
         WHERE status IN ('pending', 'authorized')",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn revoke_compromised_bundled_demo_profiles(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<u64> {
    let result = sqlx::query(
        "UPDATE users \
         SET enabled = 0, \
             key_version = CASE \
                 WHEN key_version < 9223372036854775807 THEN key_version + 1 \
                 ELSE key_version \
             END, \
             updated_at = ? \
         WHERE origin = 'legacy' AND enabled = 1 \
           AND public_key_pem IN (?, ?)",
    )
    .bind(now())
    .bind(COMPROMISED_BUNDLED_DEMO_PUBLIC_KEYS[0])
    .bind(COMPROMISED_BUNDLED_DEMO_PUBLIC_KEYS[1])
    .execute(&mut **transaction)
    .await?;
    Ok(result.rows_affected())
}

async fn ensure_user_account_capacity(
    transaction: &mut Transaction<'_, Sqlite>,
    max_user_accounts: i64,
) -> Result<()> {
    let account_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM web_accounts WHERE role = 'user'")
            .fetch_one(&mut **transaction)
            .await?;
    if account_count >= max_user_accounts {
        return Err(UserRepositoryError::UserAccountCapacity);
    }
    Ok(())
}

async fn validate_schema(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    require_columns(
        transaction,
        "users",
        &[
            "username",
            "public_key_pem",
            "permissions",
            "enabled",
            "origin",
            "key_version",
            "expires_at",
            "created_at",
            "updated_at",
        ],
    )
    .await?;
    require_columns(transaction, "app_metadata", &["key", "value"]).await?;
    require_columns(
        transaction,
        "web_accounts",
        &[
            "account_id",
            "login_name",
            "password_hash",
            "role",
            "status",
            "linked_username",
            "display_name",
            "email",
            "avatar_url",
            "auth_version",
            "last_login_at",
            "created_at",
            "updated_at",
        ],
    )
    .await?;
    require_columns(
        transaction,
        "external_identities",
        &["provider", "subject", "account_id"],
    )
    .await?;
    require_columns(
        transaction,
        "user_private_keys",
        &[
            "username",
            "encrypted_private_key",
            "key_version",
            "updated_at",
        ],
    )
    .await?;
    require_columns(
        transaction,
        "key_generation_requests",
        &[
            "request_id",
            "account_id",
            "kind",
            "status",
            "expected_key_version",
            "reviewer_account_id",
            "requested_at",
            "reviewed_at",
            "approved_expires_at",
        ],
    )
    .await?;
    require_columns(
        transaction,
        "user_access_records",
        &[
            "record_id",
            "username",
            "protocol",
            "target_host",
            "target_port",
            "access_count",
            "accessed_at",
        ],
    )
    .await?;
    require_columns(
        transaction,
        "agent_device_authorizations",
        &[
            "device_code_hash",
            "user_code_hash",
            "client_name",
            "platform",
            "status",
            "authorized_account_id",
            "authorized_auth_version",
            "created_at",
            "expires_at",
            "authorized_at",
            "consumed_at",
            "last_polled_at",
        ],
    )
    .await?;
    let retention_days: Option<String> =
        sqlx::query_scalar("SELECT value FROM app_metadata WHERE key = ?")
            .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
            .fetch_optional(&mut **transaction)
            .await?;
    let Some(retention_days) = retention_days else {
        return Err(UserRepositoryError::InvalidSchema(
            "app_metadata 缺少 access_log_retention_days".to_string(),
        ));
    };
    parse_retention_days(&retention_days).map(|_| ())
}

async fn require_columns(
    transaction: &mut Transaction<'_, Sqlite>,
    table: &str,
    required: &[&str],
) -> Result<()> {
    let columns = table_columns(transaction, table).await?;
    if columns.is_empty() {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "{table} 表不存在或没有字段"
        )));
    }
    for required in required {
        if !columns.iter().any(|column| column == required) {
            return Err(UserRepositoryError::InvalidSchema(format!(
                "{table} 表缺少字段 {required}"
            )));
        }
    }
    Ok(())
}

async fn table_columns(
    transaction: &mut Transaction<'_, Sqlite>,
    table: &str,
) -> Result<Vec<String>> {
    // table 只来自本文件中的常量，不接受外部输入。
    let query = format!("PRAGMA table_info({table})");
    sqlx::query(&query)
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|row| row.try_get("name"))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn insert_profile(
    transaction: &mut Transaction<'_, Sqlite>,
    profile: &NewUser,
    timestamp: i64,
) -> Result<()> {
    let result = sqlx::query(
        "INSERT INTO users \
         (username, public_key_pem, permissions, enabled, origin, key_version, \
          expires_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?) ON CONFLICT(username) DO NOTHING",
    )
    .bind(&profile.username)
    .bind(&profile.public_key_pem)
    .bind(encode_permissions(&profile.permissions))
    .bind(profile.enabled)
    .bind(profile.origin.as_str())
    .bind(profile.expires_at)
    .bind(timestamp)
    .bind(timestamp)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 0 {
        return Err(UserRepositoryError::Conflict(profile.username.clone()));
    }
    Ok(())
}

async fn ensure_account_identifiers_available(
    transaction: &mut Transaction<'_, Sqlite>,
    account_id: &str,
    login_name: &str,
    linked_username: Option<&str>,
) -> Result<()> {
    let account_id_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM web_accounts WHERE account_id = ?)")
            .bind(account_id)
            .fetch_one(&mut **transaction)
            .await?;
    if account_id_exists {
        return Err(UserRepositoryError::Conflict(account_id.to_string()));
    }
    let login_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM web_accounts WHERE login_name = ?)")
            .bind(login_name)
            .fetch_one(&mut **transaction)
            .await?;
    if login_exists {
        return Err(UserRepositoryError::Conflict(login_name.to_string()));
    }
    if let Some(username) = linked_username {
        let profile_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)")
                .bind(username)
                .fetch_one(&mut **transaction)
                .await?;
        if profile_exists {
            return Err(UserRepositoryError::Conflict(username.to_string()));
        }
    }
    Ok(())
}

async fn ensure_external_identity_available(
    transaction: &mut Transaction<'_, Sqlite>,
    identity: &ExternalIdentity,
) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM external_identities WHERE provider = ? AND subject = ?)",
    )
    .bind(&identity.provider)
    .bind(&identity.subject)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        return Err(UserRepositoryError::ExternalIdentityConflict {
            provider: identity.provider.clone(),
            subject: identity.subject.clone(),
        });
    }
    Ok(())
}

async fn guard_last_admin(
    transaction: &mut Transaction<'_, Sqlite>,
    current: &WebAccount,
    target_role: Option<AccountRole>,
    target_status: Option<AccountStatus>,
) -> Result<()> {
    let currently_active_admin =
        current.role == AccountRole::Admin && current.status == AccountStatus::Active;
    let remains_active_admin = target_role
        .zip(target_status)
        .is_some_and(|(role, status)| {
            role == AccountRole::Admin && status == AccountStatus::Active
        });
    if !currently_active_admin || remains_active_admin {
        return Ok(());
    }
    let other_admin_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM web_accounts \
         WHERE role = 'admin' AND status = 'active' AND account_id <> ?)",
    )
    .bind(&current.account_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !other_admin_exists {
        return Err(UserRepositoryError::LastAdmin);
    }
    Ok(())
}

async fn fetch_account_by_id(
    connection: &mut SqliteConnection,
    account_id: &str,
) -> Result<Option<WebAccount>> {
    let query = format!("SELECT {ACCOUNT_SELECT} FROM web_accounts WHERE account_id = ?");
    sqlx::query(&query)
        .bind(account_id)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_account)
        .transpose()
}

async fn fetch_account_by_login(
    connection: &mut SqliteConnection,
    login_name: &str,
) -> Result<Option<WebAccount>> {
    let query = format!("SELECT {ACCOUNT_SELECT} FROM web_accounts WHERE login_name = ?");
    sqlx::query(&query)
        .bind(login_name)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_account)
        .transpose()
}

async fn fetch_key_request_by_id(
    connection: &mut SqliteConnection,
    request_id: &str,
) -> Result<Option<KeyGenerationRequest>> {
    let query =
        format!("SELECT {KEY_REQUEST_SELECT} FROM key_generation_requests WHERE request_id = ?");
    sqlx::query(&query)
        .bind(request_id)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_key_request)
        .transpose()
}

async fn fetch_pending_key_request_for_account(
    connection: &mut SqliteConnection,
    account_id: &str,
) -> Result<Option<KeyGenerationRequest>> {
    let query = format!(
        "SELECT {KEY_REQUEST_SELECT} FROM key_generation_requests \
         WHERE account_id = ? AND status = 'pending' LIMIT 1"
    );
    sqlx::query(&query)
        .bind(account_id)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_key_request)
        .transpose()
}

async fn fetch_agent_device_authorization_by_user_code(
    connection: &mut SqliteConnection,
    user_code_hash: &str,
) -> Result<Option<AgentDeviceAuthorization>> {
    let query = format!(
        "SELECT {DEVICE_AUTHORIZATION_SELECT} FROM agent_device_authorizations \
         WHERE user_code_hash = ?"
    );
    sqlx::query(&query)
        .bind(user_code_hash)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_agent_device_authorization)
        .transpose()
}

async fn fetch_profile(
    connection: &mut SqliteConnection,
    username: &str,
) -> Result<Option<UserRecord>> {
    let query = format!("SELECT {USER_SELECT} FROM users WHERE username = ?");
    sqlx::query(&query)
        .bind(username)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_user)
        .transpose()
}

async fn fetch_managed_for_account(
    connection: &mut SqliteConnection,
    account: WebAccount,
) -> Result<ManagedUser> {
    let profile = match account.linked_username.as_deref() {
        Some(username) => Some(fetch_profile(connection, username).await?.ok_or_else(|| {
            UserRepositoryError::InvalidSchema(format!(
                "账号 {} 关联的用户 {username} 不存在",
                account.account_id
            ))
        })?),
        None => None,
    };
    let has_private_key = if let Some(profile) = &profile {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_private_keys WHERE username = ?)")
            .bind(&profile.username)
            .fetch_one(&mut *connection)
            .await?
    } else {
        false
    };
    let providers = sqlx::query(
        "SELECT provider, subject FROM external_identities \
         WHERE account_id = ? ORDER BY provider COLLATE BINARY, subject COLLATE BINARY",
    )
    .bind(&account.account_id)
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .map(|row| {
        Ok(ExternalIdentity {
            provider: row.try_get("provider")?,
            subject: row.try_get("subject")?,
        })
    })
    .collect::<Result<Vec<_>>>()?;
    Ok(ManagedUser {
        account: Some(account),
        profile,
        has_private_key,
        providers,
    })
}

fn row_to_user(row: SqliteRow) -> Result<UserRecord> {
    let username: String = row.try_get("username")?;
    let permissions_encoded: String = row.try_get("permissions")?;
    let permissions = decode_permissions(&permissions_encoded).map_err(|error| {
        UserRepositoryError::InvalidSchema(format!("用户 {username} 的 permissions 无效：{error}"))
    })?;
    let enabled: i64 = row.try_get("enabled")?;
    let enabled = match enabled {
        0 => false,
        1 => true,
        value => {
            return Err(UserRepositoryError::InvalidSchema(format!(
                "用户 {username} 的 enabled 值无效：{value}"
            )));
        }
    };
    let origin_encoded: String = row.try_get("origin")?;
    let origin = UserOrigin::parse(&origin_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "用户 {username} 的 origin 值无效：{origin_encoded}"
        ))
    })?;
    let key_version: i64 = row.try_get("key_version")?;
    if key_version < 1 {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "用户 {username} 的 key_version 值无效：{key_version}"
        )));
    }
    Ok(UserRecord {
        username,
        public_key_pem: row.try_get("public_key_pem")?,
        permissions,
        enabled,
        origin,
        key_version,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_account(row: SqliteRow) -> Result<WebAccount> {
    let account_id: String = row.try_get("account_id")?;
    let role_encoded: String = row.try_get("role")?;
    let role = AccountRole::parse(&role_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "账号 {account_id} 的 role 值无效：{role_encoded}"
        ))
    })?;
    let status_encoded: String = row.try_get("status")?;
    let status = AccountStatus::parse(&status_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "账号 {account_id} 的 status 值无效：{status_encoded}"
        ))
    })?;
    let auth_version: i64 = row.try_get("auth_version")?;
    if auth_version < 1 {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "账号 {account_id} 的 auth_version 值无效：{auth_version}"
        )));
    }
    Ok(WebAccount {
        account_id,
        login_name: row.try_get("login_name")?,
        role,
        status,
        linked_username: row.try_get("linked_username")?,
        display_name: row.try_get("display_name")?,
        email: row.try_get("email")?,
        avatar_url: row.try_get("avatar_url")?,
        auth_version,
        last_login_at: row.try_get("last_login_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_encrypted_private_key(row: SqliteRow) -> Result<EncryptedPrivateKey> {
    Ok(EncryptedPrivateKey {
        username: row.try_get("username")?,
        encrypted_private_key: row.try_get("encrypted_private_key")?,
        key_version: row.try_get("key_version")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_key_request(row: SqliteRow) -> Result<KeyGenerationRequest> {
    let request_id: String = row.try_get("request_id")?;
    let kind_encoded: String = row.try_get("kind")?;
    let kind = KeyRequestKind::parse(&kind_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "密钥申请 {request_id} 的 kind 值无效：{kind_encoded}"
        ))
    })?;
    let status_encoded: String = row.try_get("status")?;
    let status = KeyRequestStatus::parse(&status_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "密钥申请 {request_id} 的 status 值无效：{status_encoded}"
        ))
    })?;
    let expected_key_version: Option<i64> = row.try_get("expected_key_version")?;
    let valid_expected_version = match kind {
        KeyRequestKind::Initial => expected_key_version.is_none(),
        KeyRequestKind::Rotate => expected_key_version.is_some_and(|version| version >= 1),
    };
    if !valid_expected_version {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "密钥申请 {request_id} 的 expected_key_version 与 kind 不一致"
        )));
    }
    Ok(KeyGenerationRequest {
        request_id,
        account_id: row.try_get("account_id")?,
        kind,
        status,
        expected_key_version,
        reviewer_account_id: row.try_get("reviewer_account_id")?,
        requested_at: row.try_get("requested_at")?,
        reviewed_at: row.try_get("reviewed_at")?,
        approved_expires_at: row.try_get("approved_expires_at")?,
    })
}

fn row_to_access_record(row: SqliteRow) -> Result<AccessRecord> {
    let record_id: i64 = row.try_get("record_id")?;
    let protocol_encoded: String = row.try_get("protocol")?;
    let protocol = AccessProtocol::parse(&protocol_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "访问记录 {record_id} 的 protocol 值无效：{protocol_encoded}"
        ))
    })?;
    let target_port: i64 = row.try_get("target_port")?;
    let target_port = u16::try_from(target_port)
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| {
            UserRepositoryError::InvalidSchema(format!(
                "访问记录 {record_id} 的 target_port 值无效：{target_port}"
            ))
        })?;
    Ok(AccessRecord {
        record_id,
        username: row.try_get("username")?,
        protocol,
        target_host: row.try_get("target_host")?,
        target_port,
        access_count: u64::try_from(row.try_get::<i64, _>("access_count")?)
            .ok()
            .filter(|count| *count > 0)
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema(format!(
                    "访问记录 {record_id} 的 access_count 无效"
                ))
            })?,
        accessed_at: row.try_get("accessed_at")?,
    })
}

fn row_to_agent_device_authorization(row: SqliteRow) -> Result<AgentDeviceAuthorization> {
    let device_code_hash: String = row.try_get("device_code_hash")?;
    let status_encoded: String = row.try_get("status")?;
    let status = AgentDeviceAuthorizationStatus::parse(&status_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "Agent challenge {device_code_hash} 的 status 值无效：{status_encoded}"
        ))
    })?;
    let authorization = AgentDeviceAuthorization {
        device_code_hash,
        user_code_hash: row.try_get("user_code_hash")?,
        client_name: row.try_get("client_name")?,
        platform: row.try_get("platform")?,
        status,
        authorized_account_id: row.try_get("authorized_account_id")?,
        authorized_auth_version: row.try_get("authorized_auth_version")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        authorized_at: row.try_get("authorized_at")?,
        consumed_at: row.try_get("consumed_at")?,
        last_polled_at: row.try_get("last_polled_at")?,
    };
    let valid = match authorization.status {
        AgentDeviceAuthorizationStatus::Pending => {
            authorization.authorized_account_id.is_none()
                && authorization.authorized_auth_version.is_none()
                && authorization.authorized_at.is_none()
                && authorization.consumed_at.is_none()
        }
        AgentDeviceAuthorizationStatus::Authorized => {
            authorization.authorized_account_id.is_some()
                && authorization
                    .authorized_auth_version
                    .is_some_and(|version| version >= 1)
                && authorization.authorized_at.is_some()
                && authorization.consumed_at.is_none()
        }
        AgentDeviceAuthorizationStatus::Denied => {
            authorization.authorized_account_id.is_some()
                && authorization.authorized_auth_version.is_none()
                && authorization.authorized_at.is_some()
                && authorization.consumed_at.is_none()
        }
        AgentDeviceAuthorizationStatus::Consumed => {
            authorization.authorized_account_id.is_some()
                && authorization
                    .authorized_auth_version
                    .is_some_and(|version| version >= 1)
                && authorization.authorized_at.is_some()
                && authorization.consumed_at.is_some()
        }
    };
    if !valid || authorization.expires_at <= authorization.created_at {
        return Err(UserRepositoryError::InvalidSchema(
            "Agent challenge 状态字段不一致".to_string(),
        ));
    }
    Ok(authorization)
}

fn non_pending_device_authorization_poll(
    authorization: &AgentDeviceAuthorization,
    now: i64,
) -> Result<Option<AgentDeviceAuthorizationPoll>> {
    if authorization.expires_at <= now {
        return Ok(Some(AgentDeviceAuthorizationPoll::Expired));
    }
    let result = match authorization.status {
        AgentDeviceAuthorizationStatus::Pending => return Ok(None),
        AgentDeviceAuthorizationStatus::Authorized => {
            let account_id = authorization.authorized_account_id.clone().ok_or_else(|| {
                UserRepositoryError::InvalidSchema("已授权的 Agent challenge 缺少账号".to_string())
            })?;
            let account_auth_version = authorization.authorized_auth_version.ok_or_else(|| {
                UserRepositoryError::InvalidSchema(
                    "已授权的 Agent challenge 缺少账号版本".to_string(),
                )
            })?;
            AgentDeviceAuthorizationPoll::Authorized {
                account_id,
                account_auth_version,
            }
        }
        AgentDeviceAuthorizationStatus::Denied => AgentDeviceAuthorizationPoll::Denied,
        AgentDeviceAuthorizationStatus::Consumed => AgentDeviceAuthorizationPoll::Consumed,
    };
    Ok(Some(result))
}

fn normalize_new_user(user: NewUser) -> Result<NewUser> {
    let (username, public_key_pem) = validate_user(&user.username, &user.public_key_pem)?;
    let permissions = normalize_permissions(&user.permissions)?;
    Ok(NewUser {
        username,
        public_key_pem,
        permissions,
        enabled: user.enabled,
        origin: user.origin,
        expires_at: user.expires_at,
    })
}

fn encode_permissions(permissions: &[String]) -> String {
    permissions.join(",")
}

fn decode_permissions(encoded: &str) -> std::result::Result<Vec<String>, ValidationError> {
    let permissions = if encoded.is_empty() {
        Vec::new()
    } else {
        encoded.split(',').map(ToString::to_string).collect()
    };
    normalize_permissions(&permissions)
}

fn normalize_account_id(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ValidationError::InvalidAccountField("account_id 不能为空".to_string()).into());
    }
    if value.len() > MAX_ACCOUNT_ID_BYTES {
        return Err(ValidationError::InvalidAccountField(format!(
            "account_id 不能超过 {MAX_ACCOUNT_ID_BYTES} 字节"
        ))
        .into());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ValidationError::InvalidAccountField(
            "account_id 只能包含 ASCII 字母、数字、点、下划线或连字符".to_string(),
        )
        .into());
    }
    Ok(value.to_string())
}

fn normalize_code_hash(field: &str, value: &str) -> Result<String> {
    let expected_bytes = match field {
        "device_code_hash" => DEVICE_CODE_HASH_BYTES,
        "user_code_hash" => USER_CODE_HASH_BYTES,
        _ => {
            return Err(UserRepositoryError::InvalidSchema(
                "未知的 Agent code hash 字段".to_string(),
            ));
        }
    };
    if value.len() != expected_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ValidationError::InvalidAccountField(format!(
            "{field} 必须是 {expected_bytes} 字节的 base64url SHA-256 摘要"
        ))
        .into());
    }
    Ok(value.to_string())
}

fn normalize_agent_client_name(value: &str) -> Result<String> {
    normalize_field("client_name", value, MAX_AGENT_CLIENT_NAME_BYTES)
}

fn normalize_agent_platform(value: &str) -> Result<String> {
    normalize_stable_identifier("platform", value, MAX_AGENT_PLATFORM_BYTES)
}

fn normalize_request_id(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ValidationError::InvalidAccountField("request_id 不能为空".to_string()).into());
    }
    if value.len() > MAX_REQUEST_ID_BYTES {
        return Err(ValidationError::InvalidAccountField(format!(
            "request_id 不能超过 {MAX_REQUEST_ID_BYTES} 字节"
        ))
        .into());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ValidationError::InvalidAccountField(
            "request_id 只能包含 ASCII 字母、数字、点、下划线或连字符".to_string(),
        )
        .into());
    }
    Ok(value.to_string())
}

fn normalize_access_target_host(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_ACCESS_TARGET_HOST_BYTES {
        return Err(ValidationError::InvalidAccountField(format!(
            "target_host 必须为 1..={MAX_ACCESS_TARGET_HOST_BYTES} 字节"
        ))
        .into());
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::InvalidAccountField(
            "target_host 不能包含控制字符".to_string(),
        )
        .into());
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_retention_days(retention_days: u16) -> Result<()> {
    if !(MIN_ACCESS_LOG_RETENTION_DAYS..=MAX_ACCESS_LOG_RETENTION_DAYS).contains(&retention_days) {
        return Err(ValidationError::InvalidAccountField(format!(
            "访问记录保留天数必须在 {MIN_ACCESS_LOG_RETENTION_DAYS}..={MAX_ACCESS_LOG_RETENTION_DAYS} 范围内"
        ))
        .into());
    }
    Ok(())
}

fn parse_retention_days(value: &str) -> Result<u16> {
    let retention_days = value.parse::<u16>().map_err(|_| {
        UserRepositoryError::InvalidSchema(format!(
            "access_log_retention_days 不是有效整数：{value}"
        ))
    })?;
    if !(MIN_ACCESS_LOG_RETENTION_DAYS..=MAX_ACCESS_LOG_RETENTION_DAYS).contains(&retention_days) {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "access_log_retention_days 必须在 {MIN_ACCESS_LOG_RETENTION_DAYS}..={MAX_ACCESS_LOG_RETENTION_DAYS} 范围内，实际为 {retention_days}"
        )));
    }
    Ok(retention_days)
}

fn ensure_active_normal_account(account: &WebAccount) -> Result<()> {
    if account.role != AccountRole::User {
        return Err(UserRepositoryError::KeyRequestNotEligible {
            account_id: account.account_id.clone(),
            reason: "管理员账号不能申请普通用户 Proxy 密钥".to_string(),
        });
    }
    if account.status != AccountStatus::Active {
        return Err(UserRepositoryError::KeyRequestNotEligible {
            account_id: account.account_id.clone(),
            reason: "账号已停用".to_string(),
        });
    }
    Ok(())
}

fn ensure_active_admin(account: &WebAccount) -> Result<()> {
    if account.role != AccountRole::Admin || account.status != AccountStatus::Active {
        return Err(UserRepositoryError::ReviewerNotActiveAdmin {
            account_id: account.account_id.clone(),
        });
    }
    Ok(())
}

fn normalize_provider(value: &str) -> Result<String> {
    normalize_stable_identifier("provider", value, MAX_PROVIDER_BYTES)
}

fn normalize_stable_identifier(field: &str, value: &str, max_bytes: usize) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ValidationError::InvalidAccountField(format!("{field} 不能为空")).into());
    }
    if value.len() > max_bytes {
        return Err(ValidationError::InvalidAccountField(format!(
            "{field} 不能超过 {max_bytes} 字节"
        ))
        .into());
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return Err(ValidationError::InvalidAccountField(format!(
            "{field} 只能包含 ASCII 小写字母、数字、点、下划线或连字符"
        ))
        .into());
    }
    Ok(value.to_string())
}

fn normalize_provider_subject(value: &str) -> Result<String> {
    if value.is_empty() {
        return Err(
            ValidationError::InvalidAccountField("外部身份 subject 不能为空".to_string()).into(),
        );
    }
    if value.len() > MAX_PROVIDER_SUBJECT_BYTES {
        return Err(ValidationError::InvalidAccountField(format!(
            "外部身份 subject 不能超过 {MAX_PROVIDER_SUBJECT_BYTES} 字节"
        ))
        .into());
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::InvalidAccountField(
            "外部身份 subject 不能包含控制字符".to_string(),
        )
        .into());
    }
    Ok(value.to_string())
}

fn normalize_external_identity(identity: ExternalIdentity) -> Result<ExternalIdentity> {
    Ok(ExternalIdentity {
        provider: normalize_provider(&identity.provider)?,
        subject: normalize_provider_subject(&identity.subject)?,
    })
}

fn normalize_password_hash(value: Option<String>) -> Result<Option<String>> {
    value
        .map(|value| {
            if value.is_empty() || value.len() > MAX_PASSWORD_HASH_BYTES {
                return Err(ValidationError::InvalidAccountField(format!(
                    "password_hash 必须为 1..={MAX_PASSWORD_HASH_BYTES} 字节"
                ))
                .into());
            }
            if value.chars().any(char::is_control) {
                return Err(ValidationError::InvalidAccountField(
                    "password_hash 不能包含控制字符".to_string(),
                )
                .into());
            }
            Ok(value)
        })
        .transpose()
}

fn normalize_optional_field(
    field: &str,
    value: Option<String>,
    max_bytes: usize,
) -> Result<Option<String>> {
    value
        .map(|value| normalize_field(field, &value, max_bytes))
        .transpose()
}

fn normalize_field(field: &str, value: &str, max_bytes: usize) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ValidationError::InvalidAccountField(format!("{field} 不能为空")).into());
    }
    if value.len() > max_bytes {
        return Err(ValidationError::InvalidAccountField(format!(
            "{field} 不能超过 {max_bytes} 字节"
        ))
        .into());
    }
    if value.chars().any(char::is_control) {
        return Err(
            ValidationError::InvalidAccountField(format!("{field} 不能包含控制字符")).into(),
        );
    }
    Ok(value.to_string())
}

fn validate_private_key_envelope(value: &[u8]) -> Result<()> {
    if value.is_empty() || value.len() > MAX_PRIVATE_KEY_ENVELOPE_BYTES {
        return Err(ValidationError::InvalidAccountField(format!(
            "encrypted_private_key 必须为 1..={MAX_PRIVATE_KEY_ENVELOPE_BYTES} 字节"
        ))
        .into());
    }
    Ok(())
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(unix)]
fn secure_open_and_set_mode(path: &Path, mode: u32, create: bool) -> std::io::Result<()> {
    use std::io;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    if create {
        options.create(true);
    }

    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if !create && error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "无法安全打开 SQLite 数据文件 {}（拒绝符号链接）：{error}",
                    path.display()
                ),
            ));
        }
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SQLite 数据路径不是普通文件：{}", path.display()),
        ));
    }
    let actual_mode = metadata.permissions().mode() & 0o7777;
    if actual_mode != mode {
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "无法把 SQLite 数据文件 {} 的权限从 {actual_mode:04o} 调整为 \
                         {mode:04o}：{error}",
                        path.display()
                    ),
                )
            })?;
    }
    Ok(())
}

#[cfg(unix)]
fn database_sidecar_files(database_path: &Path) -> [PathBuf; 3] {
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
fn database_files(database_path: &Path) -> [PathBuf; 4] {
    let [wal, shm, journal] = database_sidecar_files(database_path);
    [database_path.to_path_buf(), wal, shm, journal]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_proxy_permissions;
    use protocol::RsaKeyPair;
    use tempfile::TempDir;

    async fn test_store() -> (TempDir, SqliteUserRepository) {
        let directory = TempDir::new().unwrap();
        let store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
            .await
            .unwrap();
        (directory, store)
    }

    fn public_key() -> String {
        RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap()
    }

    fn managed_user(
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
        }
    }

    fn user_account(account_id: &str, login_name: &str) -> NewUserAccount {
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

    async fn create_admin(store: &SqliteUserRepository, account_id: &str) {
        let outcome = store
            .bootstrap_admin_if_none(NewAdminAccount {
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

    fn initial_approval(
        request_id: &str,
        reviewer_account_id: &str,
        username: &str,
        expires_at: i64,
    ) -> KeyRequestApproval {
        KeyRequestApproval {
            request_id: request_id.to_string(),
            reviewer_account_id: reviewer_account_id.to_string(),
            expires_at,
            material: ApprovedKeyMaterial::Initial {
                profile: NewUser::new(username, public_key(), UserOrigin::Local),
                encrypted_private_key: b"encrypted-private-key".to_vec(),
            },
        }
    }

    #[tokio::test]
    async fn initializes_key_encryption_binding_for_empty_database() {
        let (_directory, store) = test_store().await;
        let binding = store.key_encryption_binding().await.unwrap();
        assert!(binding.verifier.is_none());
        assert!(binding.sample_private_key.is_none());

        assert_eq!(
            store
                .initialize_key_encryption_verifier("empty-database-verifier")
                .await
                .unwrap(),
            "empty-database-verifier"
        );
        let binding = store.key_encryption_binding().await.unwrap();
        assert_eq!(binding.verifier.as_deref(), Some("empty-database-verifier"));
        assert!(binding.sample_private_key.is_none());
    }

    #[tokio::test]
    async fn initializes_key_encryption_binding_for_legacy_only_database() {
        let (_directory, store) = test_store().await;
        store
            .create_user_record(NewUser::new(
                "legacy-user",
                public_key(),
                UserOrigin::Legacy,
            ))
            .await
            .unwrap();

        let binding = store.key_encryption_binding().await.unwrap();
        assert!(binding.verifier.is_none());
        assert!(binding.sample_private_key.is_none());
        assert_eq!(
            store
                .initialize_key_encryption_verifier("legacy-database-verifier")
                .await
                .unwrap(),
            "legacy-database-verifier"
        );
        let binding = store.key_encryption_binding().await.unwrap();
        assert_eq!(
            binding.verifier.as_deref(),
            Some("legacy-database-verifier")
        );
        assert!(binding.sample_private_key.is_none());
    }

    #[tokio::test]
    async fn key_encryption_binding_returns_existing_encrypted_sample() {
        let (_directory, store) = test_store().await;
        store
            .create_managed_user(managed_user(
                "account-alice",
                "alice-login",
                "alice",
                AccountRole::User,
                None,
            ))
            .await
            .unwrap();
        store
            .initialize_key_encryption_verifier("managed-database-verifier")
            .await
            .unwrap();

        let binding = store.key_encryption_binding().await.unwrap();
        assert_eq!(
            binding.verifier.as_deref(),
            Some("managed-database-verifier")
        );
        let sample = binding.sample_private_key.unwrap();
        assert_eq!(sample.username, "alice");
        assert_eq!(
            sample.encrypted_private_key,
            b"encrypted-private-key".to_vec()
        );
        assert_eq!(sample.key_version, 1);
        assert!(sample.updated_at > 0);
    }

    #[tokio::test]
    async fn concurrent_and_repeated_key_encryption_initialization_never_overwrites() {
        let (_directory, store) = test_store().await;
        let (first, second) = tokio::join!(
            store.initialize_key_encryption_verifier("concurrent-verifier-a"),
            store.initialize_key_encryption_verifier("concurrent-verifier-b"),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first, second);
        assert!(
            first == "concurrent-verifier-a" || first == "concurrent-verifier-b",
            "并发初始化必须保留其中一个调用方的 verifier"
        );

        assert_eq!(
            store
                .initialize_key_encryption_verifier("replacement-verifier")
                .await
                .unwrap(),
            first
        );
        assert_eq!(
            store
                .key_encryption_binding()
                .await
                .unwrap()
                .verifier
                .as_deref(),
            Some(first.as_str())
        );
        let metadata_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM app_metadata WHERE key = ?")
                .bind(KEY_ENCRYPTION_VERIFIER_KEY)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(metadata_rows, 1);
    }

    #[tokio::test]
    async fn creates_updates_and_persists_user() {
        let (directory, store) = test_store().await;
        let created = store
            .create_user("alice", &public_key(), None)
            .await
            .unwrap();
        assert_eq!(created.permissions, default_proxy_permissions());
        assert!(created.enabled);
        assert_eq!(created.key_version, 1);

        let updated = store
            .update_user(
                "alice",
                UserUpdate {
                    permissions: Some(vec![
                        "proxy.connect.udp".to_string(),
                        "proxy.connect.tcp".to_string(),
                        "proxy.connect.udp".to_string(),
                    ]),
                    expires_at: Some(Some(1_893_456_000)),
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.expires_at, Some(1_893_456_000));
        assert_eq!(updated.permissions, default_proxy_permissions());
        drop(store);

        let reopened = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
            .await
            .unwrap();
        assert_eq!(
            reopened
                .get_user("alice")
                .await
                .unwrap()
                .unwrap()
                .expires_at,
            Some(1_893_456_000)
        );
    }

    #[tokio::test]
    async fn public_key_update_invalidates_managed_private_key() {
        let (_directory, store) = test_store().await;
        store
            .create_managed_user(managed_user(
                "account-alice",
                "alice-login",
                "alice",
                AccountRole::User,
                None,
            ))
            .await
            .unwrap();
        let original = store.get_user("alice").await.unwrap().unwrap();
        let updated = store
            .update_user(
                "alice",
                UserUpdate {
                    public_key_pem: Some(public_key()),
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.key_version, original.key_version + 1);
        assert!(
            store
                .load_encrypted_private_key("alice")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn preserves_legacy_database_profiles_without_web_accounts() {
        let (_directory, store) = test_store().await;
        let mut legacy = NewUser::new("alice", public_key(), UserOrigin::Legacy);
        legacy.expires_at = Some(1_893_456_000);
        store.create_user_record(legacy).await.unwrap();
        let user = store.get_user("alice").await.unwrap().unwrap();
        assert_eq!(user.origin, UserOrigin::Legacy);
        assert_eq!(user.permissions, default_proxy_permissions());
        assert!(user.enabled);
        assert_eq!(user.key_version, 1);
        assert_eq!(user.expires_at, Some(1_893_456_000));
        let managed = store
            .get_managed_user_by_username("alice")
            .await
            .unwrap()
            .unwrap();
        assert!(managed.account.is_none());
        assert!(!managed.has_private_key);
    }

    #[tokio::test]
    async fn account_registration_rejects_login_reserved_by_legacy_database_profile() {
        let (_directory, store) = test_store().await;
        store
            .create_user_record(NewUser::new("alice", public_key(), UserOrigin::Legacy))
            .await
            .unwrap();

        let error = store
            .create_user_account(user_account("account-alice", "alice"))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            UserRepositoryError::Conflict(ref identifier) if identifier == "alice"
        ));
        assert!(store.get_account_by_login("alice").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn account_registration_rejects_login_reserved_by_direct_profile() {
        let (_directory, store) = test_store().await;
        store
            .create_user_record(NewUser::new("bob", public_key(), UserOrigin::Admin))
            .await
            .unwrap();

        let error = store
            .create_user_account(user_account("account-bob", "bob"))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            UserRepositoryError::Conflict(ref identifier) if identifier == "bob"
        ));
        assert!(store.get_account_by_login("bob").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn managed_registration_is_atomic_on_external_identity_conflict() {
        let (_directory, store) = test_store().await;
        let identity = ExternalIdentity {
            provider: "google".to_string(),
            subject: "subject-1".to_string(),
        };
        store
            .create_managed_user(managed_user(
                "account-alice",
                "alice-login",
                "alice",
                AccountRole::User,
                Some(identity.clone()),
            ))
            .await
            .unwrap();
        let error = store
            .create_managed_user(managed_user(
                "account-bob",
                "bob-login",
                "bob",
                AccountRole::User,
                Some(identity),
            ))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            UserRepositoryError::ExternalIdentityConflict { .. }
        ));
        assert!(store.get_user("bob").await.unwrap().is_none());
        assert!(
            store
                .get_account_by_id("account-bob")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .load_encrypted_private_key("bob")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn account_only_registration_and_initial_approval_are_atomic() {
        let (_directory, store) = test_store().await;
        create_admin(&store, "admin-one").await;
        let mut account = user_account("account-alice", "alice-login");
        account.external_identity = Some(ExternalIdentity {
            provider: "google".to_string(),
            subject: "google-subject".to_string(),
        });
        let created = store.create_user_account(account).await.unwrap();
        assert_eq!(created.role, AccountRole::User);
        assert_eq!(created.status, AccountStatus::Active);
        assert!(created.linked_username.is_none());
        assert_eq!(
            store
                .get_account_by_external("google", "google-subject")
                .await
                .unwrap()
                .unwrap()
                .account_id,
            "account-alice"
        );

        let pending = store
            .submit_key_generation_request(NewKeyGenerationRequest {
                request_id: "request-initial".to_string(),
                account_id: created.account_id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(pending.kind, KeyRequestKind::Initial);
        assert_eq!(pending.status, KeyRequestStatus::Pending);
        assert_eq!(pending.expected_key_version, None);
        assert_eq!(
            store
                .get_key_generation_request("request-initial")
                .await
                .unwrap(),
            Some(pending.clone())
        );
        let conflict = store
            .submit_key_generation_request(NewKeyGenerationRequest {
                request_id: "request-duplicate".to_string(),
                account_id: created.account_id.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            conflict,
            UserRepositoryError::PendingKeyRequestConflict {
                account_id,
                request_id
            } if account_id == "account-alice" && request_id == "request-initial"
        ));

        let expires_at = now() + 3600;
        let approved = store
            .approve_key_generation_request(initial_approval(
                "request-initial",
                "admin-one",
                "alice",
                expires_at,
            ))
            .await
            .unwrap();
        assert_eq!(approved.request.status, KeyRequestStatus::Approved);
        assert_eq!(approved.request.approved_expires_at, Some(expires_at));
        let profile = approved.managed_user.profile.unwrap();
        assert_eq!(profile.username, "alice");
        assert_eq!(profile.expires_at, Some(expires_at));
        assert!(approved.managed_user.has_private_key);
        assert_eq!(
            approved
                .managed_user
                .account
                .unwrap()
                .linked_username
                .as_deref(),
            Some("alice")
        );
        assert!(
            store
                .get_pending_key_generation_request("account-alice")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .load_encrypted_private_key("alice")
                .await
                .unwrap()
                .unwrap()
                .encrypted_private_key,
            b"encrypted-private-key"
        );
    }

    #[tokio::test]
    async fn user_account_capacity_is_atomic_and_a_deleted_account_frees_a_slot() {
        let (_directory, mut store) = test_store().await;
        store.max_user_accounts = 1;
        let first_store = store.clone();
        let second_store = store.clone();
        let (first, second) = tokio::join!(
            first_store.create_user_account(user_account("account-alice", "alice-login")),
            second_store.create_user_account(user_account("account-bob", "bob-login")),
        );
        assert_eq!(
            usize::from(first.is_ok()) + usize::from(second.is_ok()),
            1,
            "BEGIN IMMEDIATE 下的容量检查与插入必须是原子的"
        );
        let capacity_error = first.err().or_else(|| second.err()).unwrap();
        assert!(matches!(
            capacity_error,
            UserRepositoryError::UserAccountCapacity
        ));

        let created_id = store
            .list_managed_users()
            .await
            .unwrap()
            .into_iter()
            .find_map(|managed| managed.account.map(|account| account.account_id))
            .unwrap();
        store.delete_managed_user(&created_id).await.unwrap();
        store
            .create_user_account(user_account("account-carol", "carol-login"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn failed_initial_approval_rolls_back_and_request_remains_pending() {
        let (_directory, store) = test_store().await;
        create_admin(&store, "admin-one").await;
        store
            .create_user_account(user_account("account-alice", "alice-login"))
            .await
            .unwrap();
        store
            .submit_key_generation_request(NewKeyGenerationRequest {
                request_id: "request-initial".to_string(),
                account_id: "account-alice".to_string(),
            })
            .await
            .unwrap();

        let error = store
            .approve_key_generation_request(KeyRequestApproval {
                request_id: "request-initial".to_string(),
                reviewer_account_id: "admin-one".to_string(),
                expires_at: now() + 3600,
                material: ApprovedKeyMaterial::Rotate {
                    public_key_pem: public_key(),
                    encrypted_private_key: b"wrong-kind-envelope".to_vec(),
                },
            })
            .await
            .unwrap_err();
        assert!(matches!(error, UserRepositoryError::StaleKeyRequest { .. }));
        assert!(store.get_user("alice").await.unwrap().is_none());
        assert!(
            store
                .get_account_by_id("account-alice")
                .await
                .unwrap()
                .unwrap()
                .linked_username
                .is_none()
        );
        assert_eq!(
            store
                .get_pending_key_generation_request("account-alice")
                .await
                .unwrap()
                .unwrap()
                .status,
            KeyRequestStatus::Pending
        );

        let past_expiration = now() - 1;
        let error = store
            .approve_key_generation_request(initial_approval(
                "request-initial",
                "admin-one",
                "alice",
                past_expiration,
            ))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            UserRepositoryError::InvalidApprovalExpiration { .. }
        ));
        assert!(store.get_user("alice").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_then_allows_a_new_request() {
        let (_directory, store) = test_store().await;
        create_admin(&store, "admin-one").await;
        store
            .create_user_account(user_account("account-alice", "alice-login"))
            .await
            .unwrap();
        store
            .submit_key_generation_request(NewKeyGenerationRequest {
                request_id: "request-one".to_string(),
                account_id: "account-alice".to_string(),
            })
            .await
            .unwrap();
        let rejected = store
            .reject_key_generation_request("request-one", "admin-one")
            .await
            .unwrap();
        assert_eq!(rejected.status, KeyRequestStatus::Rejected);
        assert_eq!(rejected.reviewer_account_id.as_deref(), Some("admin-one"));
        assert!(rejected.reviewed_at.is_some());
        assert_eq!(rejected.approved_expires_at, None);

        let next = store
            .submit_key_generation_request(NewKeyGenerationRequest {
                request_id: "request-two".to_string(),
                account_id: "account-alice".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(next.kind, KeyRequestKind::Initial);
        assert_eq!(
            store.list_pending_key_generation_requests().await.unwrap(),
            vec![next]
        );
    }

    #[tokio::test]
    async fn expired_key_can_request_and_receive_atomic_rotation() {
        let (_directory, store) = test_store().await;
        create_admin(&store, "admin-one").await;
        store
            .create_managed_user(managed_user(
                "account-alice",
                "alice-login",
                "alice",
                AccountRole::User,
                None,
            ))
            .await
            .unwrap();
        let original = store.get_user("alice").await.unwrap().unwrap();
        store
            .update_managed_user(
                "account-alice",
                ManagedUserUpdate {
                    expires_at: Some(Some(now() - 1)),
                    ..ManagedUserUpdate::default()
                },
            )
            .await
            .unwrap();
        let request = store
            .submit_key_generation_request(NewKeyGenerationRequest {
                request_id: "request-rotate".to_string(),
                account_id: "account-alice".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(request.kind, KeyRequestKind::Rotate);
        assert_eq!(request.expected_key_version, Some(original.key_version));

        let new_public_key = public_key();
        let expires_at = now() + 7200;
        let approved = store
            .approve_key_generation_request(KeyRequestApproval {
                request_id: request.request_id,
                reviewer_account_id: "admin-one".to_string(),
                expires_at,
                material: ApprovedKeyMaterial::Rotate {
                    public_key_pem: new_public_key.clone(),
                    encrypted_private_key: b"rotated-envelope".to_vec(),
                },
            })
            .await
            .unwrap();
        let profile = approved.managed_user.profile.unwrap();
        assert_eq!(
            profile.public_key_pem,
            normalize_public_key_pem(&new_public_key).unwrap()
        );
        assert_eq!(profile.key_version, original.key_version + 1);
        assert_eq!(profile.expires_at, Some(expires_at));
        let private = store
            .load_encrypted_private_key("alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(private.key_version, profile.key_version);
        assert_eq!(private.encrypted_private_key, b"rotated-envelope");
    }

    #[tokio::test]
    async fn active_key_is_ineligible_but_missing_envelope_can_be_recovered() {
        let (_directory, store) = test_store().await;
        store
            .create_managed_user(managed_user(
                "account-alice",
                "alice-login",
                "alice",
                AccountRole::User,
                None,
            ))
            .await
            .unwrap();
        let error = store
            .submit_key_generation_request(NewKeyGenerationRequest {
                request_id: "request-active".to_string(),
                account_id: "account-alice".to_string(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            UserRepositoryError::KeyRequestNotEligible { .. }
        ));

        sqlx::query("DELETE FROM user_private_keys WHERE username = 'alice'")
            .execute(&store.pool)
            .await
            .unwrap();
        let recovery = store
            .submit_key_generation_request(NewKeyGenerationRequest {
                request_id: "request-recovery".to_string(),
                account_id: "account-alice".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(recovery.kind, KeyRequestKind::Rotate);
        assert_eq!(recovery.expected_key_version, Some(1));
    }

    #[tokio::test]
    async fn rotation_approval_rechecks_disabled_profile_inside_transaction() {
        let (_directory, store) = test_store().await;
        create_admin(&store, "admin-one").await;
        store
            .create_managed_user(managed_user(
                "account-alice",
                "alice-login",
                "alice",
                AccountRole::User,
                None,
            ))
            .await
            .unwrap();
        store
            .update_managed_user(
                "account-alice",
                ManagedUserUpdate {
                    expires_at: Some(Some(now() - 1)),
                    ..ManagedUserUpdate::default()
                },
            )
            .await
            .unwrap();
        let original = store.get_user("alice").await.unwrap().unwrap();
        let original_private = store
            .load_encrypted_private_key("alice")
            .await
            .unwrap()
            .unwrap();
        store
            .submit_key_generation_request(NewKeyGenerationRequest {
                request_id: "request-disabled".to_string(),
                account_id: "account-alice".to_string(),
            })
            .await
            .unwrap();
        store
            .update_managed_user(
                "account-alice",
                ManagedUserUpdate {
                    enabled: Some(false),
                    ..ManagedUserUpdate::default()
                },
            )
            .await
            .unwrap();

        let error = store
            .approve_key_generation_request(KeyRequestApproval {
                request_id: "request-disabled".to_string(),
                reviewer_account_id: "admin-one".to_string(),
                expires_at: now() + 3600,
                material: ApprovedKeyMaterial::Rotate {
                    public_key_pem: public_key(),
                    encrypted_private_key: b"must-not-commit".to_vec(),
                },
            })
            .await
            .unwrap_err();
        assert!(matches!(error, UserRepositoryError::StaleKeyRequest { .. }));
        let after = store.get_user("alice").await.unwrap().unwrap();
        assert!(!after.enabled);
        assert_eq!(after.public_key_pem, original.public_key_pem);
        assert_eq!(after.key_version, original.key_version);
        assert_eq!(after.expires_at, original.expires_at);
        assert_eq!(
            store
                .load_encrypted_private_key("alice")
                .await
                .unwrap()
                .unwrap()
                .encrypted_private_key,
            original_private.encrypted_private_key
        );
        assert_eq!(
            store
                .get_key_generation_request("request-disabled")
                .await
                .unwrap()
                .unwrap()
                .status,
            KeyRequestStatus::Pending
        );
    }

    #[tokio::test]
    async fn concurrent_approval_only_commits_one_keypair() {
        let (_directory, store) = test_store().await;
        create_admin(&store, "admin-one").await;
        store
            .create_user_account(user_account("account-alice", "alice-login"))
            .await
            .unwrap();
        store
            .submit_key_generation_request(NewKeyGenerationRequest {
                request_id: "request-race".to_string(),
                account_id: "account-alice".to_string(),
            })
            .await
            .unwrap();
        let first_public = public_key();
        let second_public = public_key();
        let expires_at = now() + 3600;
        let first_store = store.clone();
        let second_store = store.clone();
        let first = tokio::spawn(async move {
            first_store
                .approve_key_generation_request(KeyRequestApproval {
                    request_id: "request-race".to_string(),
                    reviewer_account_id: "admin-one".to_string(),
                    expires_at,
                    material: ApprovedKeyMaterial::Initial {
                        profile: NewUser::new("alice", first_public, UserOrigin::Local),
                        encrypted_private_key: b"first-envelope".to_vec(),
                    },
                })
                .await
        });
        let second = tokio::spawn(async move {
            second_store
                .approve_key_generation_request(KeyRequestApproval {
                    request_id: "request-race".to_string(),
                    reviewer_account_id: "admin-one".to_string(),
                    expires_at,
                    material: ApprovedKeyMaterial::Initial {
                        profile: NewUser::new("alice", second_public, UserOrigin::Local),
                        encrypted_private_key: b"second-envelope".to_vec(),
                    },
                })
                .await
        });
        let (first, second) = tokio::join!(first, second);
        let results = [first.unwrap(), second.unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(UserRepositoryError::KeyRequestAlreadyReviewed { .. })
                ))
                .count(),
            1
        );
        let request = store
            .get_key_generation_request("request-race")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.status, KeyRequestStatus::Approved);
        assert_eq!(store.list_users().await.unwrap().len(), 1);
        let private = store
            .load_encrypted_private_key("alice")
            .await
            .unwrap()
            .unwrap();
        assert!(
            private.encrypted_private_key == b"first-envelope"
                || private.encrypted_private_key == b"second-envelope"
        );
    }

    #[tokio::test]
    async fn records_filters_and_purges_access_history() {
        let (_directory, store) = test_store().await;
        store
            .create_user("alice", &public_key(), None)
            .await
            .unwrap();
        store.create_user("bob", &public_key(), None).await.unwrap();
        for record in [
            NewAccessRecord {
                username: "alice".to_string(),
                protocol: AccessProtocol::Tcp,
                target_host: "example.com".to_string(),
                target_port: 443,
                accessed_at: 100,
            },
            NewAccessRecord {
                username: "alice".to_string(),
                protocol: AccessProtocol::Udp,
                target_host: "1.1.1.1".to_string(),
                target_port: 53,
                accessed_at: 101,
            },
            NewAccessRecord {
                username: "alice".to_string(),
                protocol: AccessProtocol::Tcp,
                target_host: "2001:db8::1".to_string(),
                target_port: 8443,
                accessed_at: 102,
            },
            NewAccessRecord {
                username: "bob".to_string(),
                protocol: AccessProtocol::Tcp,
                target_host: "internal.example".to_string(),
                target_port: 80,
                accessed_at: 101,
            },
        ] {
            store.record_access(record).await.unwrap();
        }

        let recent = store.list_recent_access("alice", 101, 10).await.unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].accessed_at, 102);
        assert_eq!(recent[0].target_host, "2001:db8::1");
        assert_eq!(recent[0].access_count, 1);
        assert_eq!(recent[1].protocol, AccessProtocol::Udp);
        assert_eq!(
            store.list_recent_access("alice", 0, 1).await.unwrap().len(),
            1
        );
        assert!(
            store
                .list_recent_access("bob", 102, 10)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            store
                .list_recent_access("alice", 0, MAX_ACCESS_LOG_QUERY_LIMIT + 1)
                .await
                .unwrap_err(),
            UserRepositoryError::Validation(_)
        ));

        assert_eq!(store.purge_access_records_before(102).await.unwrap(), 3);
        let remaining = store.list_recent_access("alice", 0, 10).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].accessed_at, 102);
    }

    #[tokio::test]
    async fn concurrent_accesses_to_the_same_address_increment_one_row() {
        let (directory, store) = test_store().await;
        store
            .create_user("alice", &public_key(), None)
            .await
            .unwrap();
        let second_store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
            .await
            .unwrap();

        let mut writes = Vec::new();
        for offset in 0..32_i64 {
            let repository = if offset % 2 == 0 {
                store.clone()
            } else {
                second_store.clone()
            };
            writes.push(tokio::spawn(async move {
                repository
                    .record_access(NewAccessRecord {
                        username: "alice".to_string(),
                        protocol: if offset % 2 == 0 {
                            AccessProtocol::Tcp
                        } else {
                            AccessProtocol::Udp
                        },
                        target_host: if offset % 2 == 0 {
                            "Example.COM".to_string()
                        } else {
                            "example.com".to_string()
                        },
                        target_port: if offset % 2 == 0 { 443 } else { 8443 },
                        accessed_at: 100 + offset,
                    })
                    .await
                    .unwrap();
            }));
        }
        for write in writes {
            write.await.unwrap();
        }

        let records = store.list_recent_access("alice", 0, 10).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target_host, "example.com");
        assert_eq!(records[0].target_port, 8443);
        assert_eq!(records[0].protocol, AccessProtocol::Udp);
        assert_eq!(records[0].accessed_at, 131);
        assert_eq!(records[0].access_count, 32);
    }

    #[tokio::test]
    async fn access_log_retention_defaults_to_seven_and_is_validated_and_persisted() {
        let (directory, store) = test_store().await;
        assert_eq!(
            store.get_access_log_settings().await.unwrap(),
            AccessLogSettings { retention_days: 7 }
        );
        assert_eq!(
            store.set_access_log_retention_days(30).await.unwrap(),
            AccessLogSettings { retention_days: 30 }
        );
        for invalid in [0, MAX_ACCESS_LOG_RETENTION_DAYS + 1] {
            assert!(matches!(
                store
                    .set_access_log_retention_days(invalid)
                    .await
                    .unwrap_err(),
                UserRepositoryError::Validation(_)
            ));
        }
        drop(store);
        let reopened = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
            .await
            .unwrap();
        assert_eq!(
            reopened
                .get_access_log_settings()
                .await
                .unwrap()
                .retention_days,
            30
        );
    }

    #[tokio::test]
    async fn rotates_legacy_keypair_with_cas_and_upserts_private_key() {
        let (_directory, store) = test_store().await;
        store
            .create_user("legacy-user", &public_key(), None)
            .await
            .unwrap();
        let first = store
            .rotate_keypair(KeyPairRotation {
                username: "legacy-user".to_string(),
                expected_key_version: 1,
                public_key_pem: public_key(),
                encrypted_private_key: b"first-envelope".to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(first.key_version, 2);
        let private = store
            .load_encrypted_private_key("legacy-user")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(private.key_version, 2);
        assert_eq!(private.encrypted_private_key, b"first-envelope");

        let error = store
            .rotate_keypair(KeyPairRotation {
                username: "legacy-user".to_string(),
                expected_key_version: 1,
                public_key_pem: public_key(),
                encrypted_private_key: b"stale-envelope".to_vec(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            UserRepositoryError::VersionConflict {
                expected: 1,
                actual: 2,
                ..
            }
        ));
        assert_eq!(
            store
                .load_encrypted_private_key("legacy-user")
                .await
                .unwrap()
                .unwrap()
                .encrypted_private_key,
            b"first-envelope"
        );
    }

    #[tokio::test]
    async fn protects_last_active_admin() {
        let (_directory, store) = test_store().await;
        let outcome = store
            .bootstrap_admin_if_none(NewAdminAccount {
                account_id: "admin-one".to_string(),
                login_name: "admin-one".to_string(),
                password_hash: Some("$argon2id$test".to_string()),
                display_name: None,
                email: None,
                avatar_url: None,
            })
            .await
            .unwrap();
        assert!(matches!(outcome, BootstrapOutcome::Created(_)));
        assert!(matches!(
            store
                .update_managed_user(
                    "admin-one",
                    ManagedUserUpdate {
                        status: Some(AccountStatus::Disabled),
                        ..ManagedUserUpdate::default()
                    }
                )
                .await
                .unwrap_err(),
            UserRepositoryError::LastAdmin
        ));
        assert!(matches!(
            store.delete_managed_user("admin-one").await.unwrap_err(),
            UserRepositoryError::LastAdmin
        ));

        store
            .create_managed_user(managed_user(
                "admin-two",
                "admin-two",
                "admin-two-user",
                AccountRole::Admin,
                None,
            ))
            .await
            .unwrap();
        store
            .update_managed_user(
                "admin-one",
                ManagedUserUpdate {
                    status: Some(AccountStatus::Disabled),
                    ..ManagedUserUpdate::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(store.active_admin_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn device_authorization_is_rate_limited_and_finalized_exactly_once() {
        let (_directory, store) = test_store().await;
        let managed = store
            .create_managed_user(managed_user(
                "device-account",
                "device-user",
                "device-user",
                AccountRole::User,
                None,
            ))
            .await
            .unwrap();
        let account = managed.account.unwrap();
        let profile = managed.profile.unwrap();
        let device_code_hash = "A".repeat(43);
        let user_code_hash = "B".repeat(43);
        store
            .create_agent_device_authorization(NewAgentDeviceAuthorization {
                device_code_hash: device_code_hash.clone(),
                user_code_hash: user_code_hash.clone(),
                client_name: "Alice Android".to_string(),
                platform: "android".to_string(),
                created_at: 100,
                expires_at: 700,
            })
            .await
            .unwrap();
        let record = store
            .get_agent_device_authorization_by_user_code(&user_code_hash, 100)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.status, AgentDeviceAuthorizationStatus::Pending);
        assert_eq!(record.client_name, "Alice Android");

        assert_eq!(
            store
                .poll_agent_device_authorization(&device_code_hash, 101, 5)
                .await
                .unwrap(),
            AgentDeviceAuthorizationPoll::Pending {
                retry_after_seconds: 5
            }
        );
        assert_eq!(
            store
                .poll_agent_device_authorization(&device_code_hash, 102, 5)
                .await
                .unwrap(),
            AgentDeviceAuthorizationPoll::SlowDown {
                retry_after_seconds: 4
            }
        );
        assert_eq!(
            store
                .authorize_agent_device(
                    &user_code_hash,
                    &account.account_id,
                    account.auth_version,
                    103,
                )
                .await
                .unwrap(),
            AgentDeviceAuthorizationDecision::Authorized
        );
        assert_eq!(
            store
                .authorize_agent_device(
                    &user_code_hash,
                    &account.account_id,
                    account.auth_version,
                    104,
                )
                .await
                .unwrap(),
            AgentDeviceAuthorizationDecision::AlreadyAuthorized
        );

        let first_poll = store
            .poll_agent_device_authorization(&device_code_hash, 105, 5)
            .await
            .unwrap();
        let second_poll = store
            .poll_agent_device_authorization(&device_code_hash, 105, 5)
            .await
            .unwrap();
        assert!(matches!(
            first_poll,
            AgentDeviceAuthorizationPoll::Authorized { .. }
        ));
        assert!(matches!(
            second_poll,
            AgentDeviceAuthorizationPoll::Authorized { .. }
        ));

        let claim = || AgentDeviceAuthorizationClaim {
            device_code_hash: device_code_hash.clone(),
            account_id: account.account_id.clone(),
            account_auth_version: account.auth_version,
            username: profile.username.clone(),
            permissions: profile.permissions.clone(),
            key_version: profile.key_version,
            expires_at: profile.expires_at,
            now: 106,
        };
        let first = store.clone();
        let first_claim = claim();
        let second = store.clone();
        let second_claim = claim();
        let (left, right) = tokio::join!(
            async move {
                first
                    .finalize_agent_device_authorization(first_claim)
                    .await
                    .unwrap()
            },
            async move {
                second
                    .finalize_agent_device_authorization(second_claim)
                    .await
                    .unwrap()
            }
        );
        assert!(
            matches!(
                (&left, &right),
                (
                    AgentDeviceAuthorizationFinalize::Finalized,
                    AgentDeviceAuthorizationFinalize::AlreadyFinalized
                ) | (
                    AgentDeviceAuthorizationFinalize::AlreadyFinalized,
                    AgentDeviceAuthorizationFinalize::Finalized
                )
            ),
            "并发领取必须只执行一次状态 CAS"
        );
        assert!(matches!(
            store
                .poll_agent_device_authorization(&device_code_hash, 107, 5)
                .await
                .unwrap(),
            AgentDeviceAuthorizationPoll::Consumed
        ));
    }

    #[tokio::test]
    async fn device_authorization_maintenance_is_time_controlled_and_infrequent() {
        let (_directory, store) = test_store().await;
        sqlx::query(
            "INSERT INTO agent_device_authorizations \
             (device_code_hash, user_code_hash, client_name, platform, status, \
              created_at, expires_at) \
             VALUES (?, ?, 'Old Agent', 'android', 'pending', 1, 100)",
        )
        .bind("O".repeat(43))
        .bind("P".repeat(43))
        .execute(&store.pool)
        .await
        .unwrap();

        for (suffix, now) in [("A", 100_000_i64), ("B", 100_001_i64)] {
            store
                .create_agent_device_authorization(NewAgentDeviceAuthorization {
                    device_code_hash: suffix.repeat(43),
                    user_code_hash: suffix.to_ascii_lowercase().repeat(43),
                    client_name: "Maintenance Test".to_string(),
                    platform: "android".to_string(),
                    created_at: now,
                    expires_at: now + 600,
                })
                .await
                .unwrap();
        }
        let old_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM agent_device_authorizations \
             WHERE device_code_hash = ?)",
        )
        .bind("O".repeat(43))
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!(!old_exists);
        let maintenance = store.device_authorization_maintenance.lock().await;
        assert_eq!(maintenance.next_run_at, 100_030);
        assert_eq!(maintenance.active_count, 2);
    }

    #[tokio::test]
    async fn concurrent_device_authorization_creation_keeps_cached_capacity_consistent() {
        let (_directory, store) = test_store().await;
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..64_u32 {
            let store = store.clone();
            tasks.spawn(async move {
                store
                    .create_agent_device_authorization(NewAgentDeviceAuthorization {
                        device_code_hash: format!("D{index:042}"),
                        user_code_hash: format!("U{index:042}"),
                        client_name: "Concurrent Agent".to_string(),
                        platform: "windows".to_string(),
                        created_at: 200_000,
                        expires_at: 200_600,
                    })
                    .await
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        let database_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agent_device_authorizations")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(database_count, 64);
        assert_eq!(
            store
                .device_authorization_maintenance
                .lock()
                .await
                .active_count,
            64
        );
    }

    #[tokio::test]
    async fn disables_publicly_compromised_legacy_demo_keys_until_rotated() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("users.sqlite3");
        let store = SqliteUserRepository::connect(&path).await.unwrap();
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
        store.pool.close().await;

        let reopened = SqliteUserRepository::connect(&path).await.unwrap();
        let disabled = reopened
            .get_user("compromised-demo")
            .await
            .unwrap()
            .unwrap();
        assert!(!disabled.enabled);
        assert_eq!(disabled.key_version, 2);
        reopened.pool.close().await;

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
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();
        assert!(rotated.enabled);
        assert_eq!(rotated.key_version, 3);
        reopened.pool.close().await;

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
        sqlx::query("DROP TABLE agent_device_authorizations")
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version = 4")
            .execute(&store.pool)
            .await
            .unwrap();
        store.pool.close().await;

        let reopened = SqliteUserRepository::connect(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&reopened.pool)
            .await
            .unwrap();
        assert_eq!(version, SQLITE_SCHEMA_VERSION);
        let mut transaction = reopened.pool.begin().await.unwrap();
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
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(marker, "value");
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&store.pool)
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
            .execute(&store.pool)
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
        sqlx::query("DELETE FROM app_metadata WHERE key = ?")
            .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version = 2")
            .execute(&store.pool)
            .await
            .unwrap();
        store.pool.close().await;

        let reopened = SqliteUserRepository::connect(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&reopened.pool)
            .await
            .unwrap();
        assert_eq!(version, SQLITE_SCHEMA_VERSION);
        assert!(
            table_columns(
                &mut reopened.pool.begin().await.unwrap(),
                "key_generation_requests"
            )
            .await
            .unwrap()
            .iter()
            .any(|column| column == "approved_expires_at")
        );
        let mut transaction = reopened.pool.begin().await.unwrap();
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
        sqlx::query("PRAGMA user_version = 6")
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
        assert_eq!(version, 6);
    }

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
        let store = SqliteUserRepository::connect_with_permissions(
            &path,
            SqliteFilePermissions::OwnerAndGroup,
        )
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

        let store = SqliteUserRepository::connect_with_permissions(
            &path,
            SqliteFilePermissions::OwnerAndGroup,
        )
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
        let store = SqliteUserRepository::connect_with_permissions(
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
}
