use crate::{
    AccessLogRepository, AccessLogSettings, AccessProtocol, AccessRecord, AccountRepository,
    AccountRole, AccountStatus, ApprovedKeyMaterial, BootstrapOutcome,
    DEFAULT_ACCESS_LOG_RETENTION_DAYS, EncryptedPrivateKey, ExternalIdentity, ImportOutcome,
    KeyEncryptionBinding, KeyGenerationRequest, KeyPairRotation, KeyRequestApproval,
    KeyRequestApprovalResult, KeyRequestKind, KeyRequestStatus, LoginRecord,
    MAX_ACCESS_LOG_QUERY_LIMIT, MAX_ACCESS_LOG_RETENTION_DAYS, MIN_ACCESS_LOG_RETENTION_DAYS,
    ManagedUser, ManagedUserUpdate, NewAccessRecord, NewAdminAccount, NewKeyGenerationRequest,
    NewManagedUser, NewUser, NewUserAccount, Result, UserOrigin, UserRecord, UserRepository,
    UserRepositoryError, UserUpdate, ValidationError, WebAccount, normalize_permissions,
    normalize_public_key_pem, normalize_username, parse_expires_at, validate_user,
};
use async_trait::async_trait;
use serde::{Deserialize, Deserializer, de};
use sqlx::{
    Row, Sqlite, SqliteConnection, SqlitePool, Transaction,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
    },
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use time::OffsetDateTime;
use tracing::{debug, info, instrument};

const TOML_IMPORT_MARKER: &str = "users_toml_import_v1";
const ACCESS_LOG_RETENTION_DAYS_KEY: &str = "access_log_retention_days";
const KEY_ENCRYPTION_VERIFIER_KEY: &str = "proxy_web_key_encryption_verifier_v1";
const SQLITE_SCHEMA_VERSION: i64 = 4;
const DEFAULT_PERMISSIONS_SQL: &str = "proxy.connect.tcp,proxy.connect.udp";
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

#[derive(Debug, Clone)]
pub struct SqliteUserRepository {
    pool: SqlitePool,
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct UsersToml {
    users: BTreeMap<String, TomlUser>,
}

#[derive(Debug, Deserialize)]
struct TomlUser {
    username: String,
    public_key_pem: String,
    #[serde(
        default,
        alias = "expire_at",
        deserialize_with = "deserialize_expires_at"
    )]
    expires_at: Option<String>,
}

impl SqliteUserRepository {
    #[instrument(skip(path), fields(database = %path.as_ref().display()))]
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        Self::prepare_database_file(&path)?;

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

        let store = Self { pool, path };
        store.migrate().await?;
        store.restrict_file_permissions()?;
        info!(
            database = %store.path.display(),
            schema_version = SQLITE_SCHEMA_VERSION,
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
            sqlx::query("PRAGMA user_version = 4")
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    #[instrument(skip(self, users_path), fields(users_toml = %users_path.as_ref().display()))]
    pub async fn import_users_toml_once(
        &self,
        users_path: impl AsRef<Path>,
    ) -> Result<ImportOutcome> {
        let users_path = users_path.as_ref();
        let already_handled =
            sqlx::query_scalar::<_, i64>("SELECT 1 FROM app_metadata WHERE key = ? LIMIT 1")
                .bind(TOML_IMPORT_MARKER)
                .fetch_optional(&self.pool)
                .await?
                .is_some();
        if already_handled {
            return Ok(ImportOutcome::AlreadyHandled);
        }

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let marker_result = sqlx::query(
            "INSERT INTO app_metadata (key, value) VALUES (?, 'in_progress') \
             ON CONFLICT(key) DO NOTHING",
        )
        .bind(TOML_IMPORT_MARKER)
        .execute(&mut *transaction)
        .await?;
        if marker_result.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(ImportOutcome::AlreadyHandled);
        }

        let existing_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *transaction)
            .await?;
        if existing_users > 0 {
            let existing_users = usize::try_from(existing_users).unwrap_or(usize::MAX);
            set_import_marker(
                &mut transaction,
                &format!("skipped_nonempty:{existing_users}"),
            )
            .await?;
            transaction.commit().await?;
            info!(
                users = existing_users,
                "SQLite 已有用户，跳过 users.toml 首次导入"
            );
            return Ok(ImportOutcome::SkippedNonEmptyDatabase {
                users: existing_users,
            });
        }

        if !users_path.try_exists()? {
            transaction.rollback().await?;
            debug!("users.toml 不存在，跳过首次导入");
            return Ok(ImportOutcome::SourceMissing);
        }

        // 在持有写锁时校验小型 TOML 文件，避免另一服务并发创建首个用户后仍导入。
        let content = fs::read_to_string(users_path)?;
        let users: UsersToml = toml::from_str(&content)?;
        let mut validated = Vec::with_capacity(users.users.len());
        for (key, user) in users.users {
            let (username, public_key_pem) = validate_user(&user.username, &user.public_key_pem)
                .map_err(|error| {
                    UserRepositoryError::InvalidImport(format!("用户 {key}：{error}"))
                })?;
            if key != username {
                return Err(UserRepositoryError::InvalidImport(format!(
                    "用户配置键 {key} 与 username 字段 {} 不一致",
                    user.username
                )));
            }
            let expires_at = user
                .expires_at
                .as_deref()
                .map(|value| parse_expires_at(&username, value))
                .transpose()
                .map_err(|error| UserRepositoryError::InvalidImport(error.to_string()))?;
            validated.push((username, public_key_pem, expires_at));
        }

        let now = now();
        for (username, public_key_pem, expires_at) in &validated {
            sqlx::query(
                "INSERT INTO users \
                 (username, public_key_pem, permissions, enabled, origin, key_version, \
                  expires_at, created_at, updated_at) \
                 VALUES (?, ?, ?, 1, 'legacy', 1, ?, ?, ?)",
            )
            .bind(username)
            .bind(public_key_pem)
            .bind(DEFAULT_PERMISSIONS_SQL)
            .bind(*expires_at)
            .bind(now)
            .bind(now)
            .execute(&mut *transaction)
            .await?;
        }
        set_import_marker(&mut transaction, &format!("imported:{}", validated.len())).await?;
        transaction.commit().await?;
        info!(users = validated.len(), "users.toml 已首次导入 SQLite");
        Ok(ImportOutcome::Imported {
            users: validated.len(),
        })
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
    fn prepare_database_file(path: &Path) -> Result<()> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn prepare_database_file(_path: &Path) -> Result<()> {
        Ok(())
    }

    #[cfg(unix)]
    fn restrict_file_permissions(&self) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        for path in database_files(&self.path) {
            if path.try_exists()? {
                let mut permissions = fs::metadata(&path)?.permissions();
                permissions.set_mode(0o600);
                fs::set_permissions(path, permissions)?;
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn restrict_file_permissions(&self) -> Result<()> {
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
        ensure_account_identifiers_available(&mut transaction, &account_id, &login_name, None)
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

        // UPSERT 是有意的：从 users.toml 导入的 legacy 用户没有私钥记录，也应能轮换。
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

async fn set_import_marker(transaction: &mut Transaction<'_, Sqlite>, value: &str) -> Result<()> {
    sqlx::query("UPDATE app_metadata SET value = ? WHERE key = ?")
        .bind(value)
        .bind(TOML_IMPORT_MARKER)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn deserialize_expires_at<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<toml::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };

    match value {
        toml::Value::String(expires_at) => Ok(Some(expires_at)),
        toml::Value::Datetime(expires_at) => Ok(Some(expires_at.to_string())),
        toml::Value::Integer(expires_at) => Ok(Some(expires_at.to_string())),
        _ => Err(de::Error::custom(
            "expires_at must be a RFC3339 datetime string or Unix timestamp",
        )),
    }
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(unix)]
fn database_files(database_path: &Path) -> [PathBuf; 3] {
    let auxiliary_path = |suffix: &str| {
        let mut path = database_path.as_os_str().to_os_string();
        path.push(suffix);
        PathBuf::from(path)
    };
    [
        database_path.to_path_buf(),
        auxiliary_path("-wal"),
        auxiliary_path("-shm"),
    ]
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
    async fn imports_toml_as_legacy_public_profiles_only() {
        let (directory, store) = test_store().await;
        let users_path = directory.path().join("users.toml");
        fs::write(
            &users_path,
            format!(
                r#"
[users.alice]
username = "alice"
public_key_pem = """
{}"""
expires_at = "2030-01-01T00:00:00Z"
"#,
                public_key()
            ),
        )
        .unwrap();

        assert_eq!(
            store.import_users_toml_once(&users_path).await.unwrap(),
            ImportOutcome::Imported { users: 1 }
        );
        let user = store.get_user("alice").await.unwrap().unwrap();
        assert_eq!(user.origin, UserOrigin::Legacy);
        assert_eq!(user.permissions, default_proxy_permissions());
        assert!(user.enabled);
        assert_eq!(user.key_version, 1);
        let managed = store
            .get_managed_user_by_username("alice")
            .await
            .unwrap()
            .unwrap();
        assert!(managed.account.is_none());
        assert!(!managed.has_private_key);

        fs::write(&users_path, "this is no longer valid TOML").unwrap();
        assert_eq!(
            store.import_users_toml_once(&users_path).await.unwrap(),
            ImportOutcome::AlreadyHandled
        );
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
        sqlx::query(
            "INSERT INTO app_metadata (key, value) VALUES ('users_toml_import_v1', 'imported:1')",
        )
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
            .bind(TOML_IMPORT_MARKER)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(marker, "imported:1");
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
        sqlx::query("PRAGMA user_version = 4")
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
        assert_eq!(version, 4);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn database_and_wal_files_are_owner_only() {
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
}
