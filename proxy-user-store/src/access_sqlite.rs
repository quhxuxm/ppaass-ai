use crate::{
    AccessLogRepository, AccessLogSettings, AccessProtocol, AccessRecord,
    DEFAULT_ACCESS_LOG_RETENTION_DAYS, MAX_ACCESS_LOG_QUERY_LIMIT, MAX_ACCESS_LOG_RETENTION_DAYS,
    MIN_ACCESS_LOG_RETENTION_DAYS, NewAccessRecord, Result, SqliteFilePermissions,
    UserRepositoryError, ValidationError, normalize_username,
};
use async_trait::async_trait;
use sqlx::{
    Connection, Row, SqlitePool,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
    },
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{info, instrument};

const ACCESS_LOG_SCHEMA_VERSION: i64 = 1;
const ACCESS_LOG_RETENTION_DAYS_KEY: &str = "access_log_retention_days";
const LEGACY_USER_DATABASE_IMPORT_KEY: &str = "legacy_user_database_access_import_v1";
const LEGACY_USER_DATABASE_CLEANUP_KEY: &str = "access_log_split_cleanup_v1";
const LEGACY_USER_DATABASE_CHECKPOINT_KEY: &str = "access_log_split_checkpoint_v1";
const MAX_ACCESS_TARGET_HOST_BYTES: usize = 1_024;
const ACCESS_RECORD_SELECT: &str = "record_id, username, protocol, target_host, target_port, \
                                    access_count, accessed_at";

/// SQLite adapter dedicated to proxy access history.
///
/// It deliberately has no account or key-management implementation. Deployments can therefore
/// grant the Proxy process write access to this database without granting write access to the
/// user/account database.
#[derive(Debug, Clone)]
pub struct SqliteAccessLogRepository {
    pool: SqlitePool,
    path: PathBuf,
    file_permissions: SqliteFilePermissions,
}

impl SqliteAccessLogRepository {
    /// Rejects configurations that would collapse the trust boundary back into one file.
    ///
    /// Call this before opening the access database so a mistaken group-writable policy can
    /// never chmod the user database.
    pub fn validate_distinct_database_paths(
        access_database_path: impl AsRef<Path>,
        user_database_path: impl AsRef<Path>,
    ) -> Result<()> {
        if same_database_path(access_database_path.as_ref(), user_database_path.as_ref())? {
            return Err(UserRepositoryError::InvalidDatabaseLayout(
                "访问记录数据库必须与用户数据库使用不同文件".to_string(),
            ));
        }
        Ok(())
    }

    #[instrument(skip(path), fields(database = %path.as_ref().display()))]
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        Self::connect_with_permissions(path, SqliteFilePermissions::OwnerOnly).await
    }

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
        prepare_database_files(&path, file_permissions)?;

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
            // Retention deletes must scrub deleted payloads instead of leaving host history in
            // SQLite freelist pages. A zero WAL size limit truncates reset WAL files.
            .pragma("secure_delete", "ON")
            .pragma("journal_size_limit", "0");
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await?;
        let repository = Self {
            pool,
            path,
            file_permissions,
        };
        repository.migrate().await?;
        repository.apply_file_permissions()?;
        info!(
            database = %repository.path.display(),
            schema_version = ACCESS_LOG_SCHEMA_VERSION,
            file_permissions = ?repository.file_permissions,
            "SQLite 访问记录数据库已就绪"
        );
        Ok(repository)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    async fn migrate(&self) -> Result<()> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let schema_version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut *transaction)
            .await?;
        if schema_version > ACCESS_LOG_SCHEMA_VERSION {
            return Err(UserRepositoryError::InvalidSchema(format!(
                "访问记录数据库版本 {schema_version} 高于当前支持版本 \
                 {ACCESS_LOG_SCHEMA_VERSION}"
            )));
        }
        if schema_version == 0 {
            sqlx::query(
                r#"
                CREATE TABLE app_metadata (
                    key TEXT NOT NULL PRIMARY KEY,
                    value TEXT NOT NULL
                )
                "#,
            )
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                r#"
                CREATE TABLE user_access_records (
                    record_id INTEGER NOT NULL PRIMARY KEY,
                    username TEXT COLLATE BINARY NOT NULL,
                    protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
                    target_host TEXT COLLATE NOCASE NOT NULL
                        CHECK(length(target_host) > 0 AND length(target_host) <= 1024),
                    target_port INTEGER NOT NULL CHECK(target_port BETWEEN 1 AND 65535),
                    access_count INTEGER NOT NULL CHECK(access_count >= 1),
                    accessed_at INTEGER NOT NULL,
                    legacy_access_count INTEGER NOT NULL DEFAULT 0
                        CHECK(legacy_access_count >= 0
                              AND legacy_access_count <= access_count),
                    UNIQUE(username, target_host)
                )
                "#,
            )
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "CREATE INDEX idx_access_records_user_time \
                 ON user_access_records(username, accessed_at DESC, record_id DESC)",
            )
            .execute(&mut *transaction)
            .await?;
            sqlx::query("CREATE INDEX idx_access_records_time ON user_access_records(accessed_at)")
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO app_metadata (key, value) VALUES (?, ?)")
                .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
                .bind(DEFAULT_ACCESS_LOG_RETENTION_DAYS.to_string())
                .execute(&mut *transaction)
                .await?;
            sqlx::query("PRAGMA user_version = 1")
                .execute(&mut *transaction)
                .await?;
        }

        // A zero-row select validates the columns and catches an unrelated SQLite file early.
        sqlx::query(
            "SELECT record_id, username, protocol, target_host, target_port, access_count, \
             accessed_at, legacy_access_count FROM user_access_records LIMIT 0",
        )
        .execute(&mut *transaction)
        .await?;
        let retention_days: Option<String> =
            sqlx::query_scalar("SELECT value FROM app_metadata WHERE key = ?")
                .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
                .fetch_optional(&mut *transaction)
                .await?;
        let retention_days = retention_days.ok_or_else(|| {
            UserRepositoryError::InvalidSchema(
                "访问记录数据库缺少 access_log_retention_days".to_string(),
            )
        })?;
        parse_retention_days(&retention_days)?;
        transaction.commit().await?;
        Ok(())
    }

    /// Imports access history retained in the pre-split user database exactly once.
    ///
    /// The destination tracks how much of every aggregate came from the legacy database. This
    /// makes a retry after a crash idempotent while preserving accesses concurrently recorded in
    /// the new database.
    #[instrument(
        skip(self, user_database_path),
        fields(
            access_database = %self.path.display(),
            user_database = %user_database_path.as_ref().display()
        )
    )]
    pub async fn import_legacy_user_database_once(
        &self,
        user_database_path: impl AsRef<Path>,
    ) -> Result<u64> {
        let user_database_path = user_database_path.as_ref();
        Self::validate_distinct_database_paths(&self.path, user_database_path)?;

        let mut connection = self.pool.acquire().await?;
        sqlx::query("ATTACH DATABASE ? AS legacy_user_database")
            .bind(user_database_path.to_string_lossy().as_ref())
            .execute(&mut *connection)
            .await?;

        let import_result = async {
            let mut transaction = connection.begin_with("BEGIN IMMEDIATE").await?;
            let imported: Option<String> =
                sqlx::query_scalar("SELECT value FROM main.app_metadata WHERE key = ?")
                    .bind(LEGACY_USER_DATABASE_IMPORT_KEY)
                    .fetch_optional(&mut *transaction)
                    .await?;
            if imported.is_some() {
                transaction.commit().await?;
                return Ok(0);
            }

            let legacy_table_exists: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM legacy_user_database.sqlite_schema \
                 WHERE type = 'table' AND name = 'user_access_records' LIMIT 1",
            )
            .fetch_optional(&mut *transaction)
            .await?;
            let rows_affected = if legacy_table_exists.is_some() {
                // `WHERE 1` avoids SQLite parsing ON as a SELECT join clause.
                sqlx::query(
                    r#"
                    INSERT INTO main.user_access_records (
                        username,
                        protocol,
                        target_host,
                        target_port,
                        access_count,
                        accessed_at,
                        legacy_access_count
                    )
                    SELECT
                        username,
                        protocol,
                        lower(target_host),
                        target_port,
                        access_count,
                        accessed_at,
                        access_count
                    FROM legacy_user_database.user_access_records
                    WHERE 1
                    ON CONFLICT(username, target_host) DO UPDATE SET
                        protocol = CASE
                            WHEN excluded.accessed_at >= user_access_records.accessed_at
                            THEN excluded.protocol ELSE user_access_records.protocol END,
                        target_port = CASE
                            WHEN excluded.accessed_at >= user_access_records.accessed_at
                            THEN excluded.target_port ELSE user_access_records.target_port END,
                        access_count = user_access_records.access_count
                            - user_access_records.legacy_access_count
                            + excluded.legacy_access_count,
                        accessed_at = MAX(
                            user_access_records.accessed_at,
                            excluded.accessed_at
                        ),
                        legacy_access_count = excluded.legacy_access_count
                    "#,
                )
                .execute(&mut *transaction)
                .await?
                .rows_affected()
            } else {
                0
            };

            let legacy_retention: Option<String> = sqlx::query_scalar(
                "SELECT value FROM legacy_user_database.app_metadata WHERE key = ?",
            )
            .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
            .fetch_optional(&mut *transaction)
            .await?;
            if let Some(legacy_retention) = legacy_retention {
                parse_retention_days(&legacy_retention)?;
                sqlx::query("UPDATE main.app_metadata SET value = ? WHERE key = ?")
                    .bind(legacy_retention)
                    .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
                    .execute(&mut *transaction)
                    .await?;
            }
            sqlx::query("INSERT INTO main.app_metadata (key, value) VALUES (?, ?)")
                .bind(LEGACY_USER_DATABASE_IMPORT_KEY)
                .bind(format!("imported:{rows_affected}"))
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            Ok(rows_affected)
        }
        .await;

        let detach_result = sqlx::query("DETACH DATABASE legacy_user_database")
            .execute(&mut *connection)
            .await;
        match (import_result, detach_result) {
            (Ok(rows), Ok(_)) => {
                info!(rows, "旧用户数据库中的访问记录迁移完成");
                Ok(rows)
            }
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    /// Verifies the split migration and then removes legacy access rows from the user database.
    ///
    /// Rows at or after `retention_cutoff` must be represented by the destination's immutable
    /// `legacy_access_count` before any source deletion occurs. Older rows may already have been
    /// purged from the destination and are intentionally eligible for deletion. The source delete
    /// and cleanup marker share one transaction, making retries safe.
    #[instrument(
        skip(self, user_database_path),
        fields(
            access_database = %self.path.display(),
            user_database = %user_database_path.as_ref().display(),
            retention_cutoff
        )
    )]
    pub async fn cleanup_legacy_user_database_access_records(
        &self,
        user_database_path: impl AsRef<Path>,
        retention_cutoff: i64,
    ) -> Result<u64> {
        if retention_cutoff < 0 {
            return Err(ValidationError::InvalidAccountField(
                "retention_cutoff 不能为负数".to_string(),
            )
            .into());
        }
        let user_database_path = user_database_path.as_ref();
        Self::validate_distinct_database_paths(&self.path, user_database_path)?;

        let mut connection = self.pool.acquire().await?;
        sqlx::query("ATTACH DATABASE ? AS legacy_user_database")
            .bind(user_database_path.to_string_lossy().as_ref())
            .execute(&mut *connection)
            .await?;
        // This setting belongs to the attached user database connection. It ensures the one-time
        // privacy cleanup overwrites deleted B-tree payloads before the WAL is checkpointed.
        sqlx::query("PRAGMA legacy_user_database.secure_delete = ON")
            .execute(&mut *connection)
            .await?;

        let cleanup_result = async {
            let mut transaction = connection.begin_with("BEGIN IMMEDIATE").await?;
            let imported: Option<String> =
                sqlx::query_scalar("SELECT value FROM main.app_metadata WHERE key = ?")
                    .bind(LEGACY_USER_DATABASE_IMPORT_KEY)
                    .fetch_optional(&mut *transaction)
                    .await?;
            if imported.is_none() {
                return Err(UserRepositoryError::InvalidDatabaseLayout(
                    "尚未完成旧用户数据库访问记录复制，拒绝清理源数据".to_string(),
                ));
            }

            let already_cleaned: Option<String> = sqlx::query_scalar(
                "SELECT value FROM legacy_user_database.app_metadata WHERE key = ?",
            )
            .bind(LEGACY_USER_DATABASE_CLEANUP_KEY)
            .fetch_optional(&mut *transaction)
            .await?;
            if already_cleaned.is_some() {
                let unexpected_rows: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM legacy_user_database.user_access_records",
                )
                .fetch_one(&mut *transaction)
                .await?;
                if unexpected_rows != 0 {
                    return Err(UserRepositoryError::InvalidSchema(format!(
                        "旧用户数据库在访问记录清理完成后又出现 {unexpected_rows} 行；\
                         请停止仍在写主库的旧版 Proxy"
                    )));
                }
                let checkpoint_completed: Option<String> =
                    sqlx::query_scalar("SELECT value FROM main.app_metadata WHERE key = ?")
                        .bind(LEGACY_USER_DATABASE_CHECKPOINT_KEY)
                        .fetch_optional(&mut *transaction)
                        .await?;
                transaction.commit().await?;
                return Ok((0, checkpoint_completed.is_none()));
            }

            let uncovered_rows: i64 = sqlx::query_scalar(
                r#"
                SELECT COUNT(*)
                FROM legacy_user_database.user_access_records AS legacy
                LEFT JOIN main.user_access_records AS migrated
                  ON migrated.username = legacy.username
                 AND migrated.target_host = lower(legacy.target_host)
                WHERE legacy.accessed_at >= ?
                  AND (
                    migrated.record_id IS NULL
                    OR migrated.legacy_access_count < legacy.access_count
                  )
                "#,
            )
            .bind(retention_cutoff)
            .fetch_one(&mut *transaction)
            .await?;
            if uncovered_rows != 0 {
                return Err(UserRepositoryError::InvalidDatabaseLayout(format!(
                    "访问记录目标库缺少 {uncovered_rows} 行仍在保留期内的旧数据；\
                     为防止丢失，拒绝清理用户数据库"
                )));
            }

            let source_rows: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM legacy_user_database.user_access_records")
                    .fetch_one(&mut *transaction)
                    .await?;
            sqlx::query("DELETE FROM legacy_user_database.user_access_records")
                .execute(&mut *transaction)
                .await?;
            sqlx::query(
                "INSERT INTO legacy_user_database.app_metadata (key, value) VALUES (?, ?) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )
            .bind(LEGACY_USER_DATABASE_CLEANUP_KEY)
            .bind(format!("cleaned:{source_rows}"))
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            let source_rows = u64::try_from(source_rows).map_err(|_| {
                UserRepositoryError::InvalidSchema(
                    "旧用户数据库访问记录数量不能表示为 u64".to_string(),
                )
            })?;
            Ok((source_rows, true))
        }
        .await;

        let checkpoint_result = if matches!(&cleanup_result, Ok((_, true))) {
            async {
                let checkpoint: (i64, i64, i64) =
                    sqlx::query_as("PRAGMA legacy_user_database.wal_checkpoint(TRUNCATE)")
                        .fetch_one(&mut *connection)
                        .await?;
                validate_checkpoint(checkpoint, "旧用户数据库")?;
                // Store completion in the access database so writing the marker cannot recreate
                // a WAL frame in the just-checkpointed user database.
                sqlx::query(
                    "INSERT INTO main.app_metadata (key, value) VALUES (?, 'completed') \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                )
                .bind(LEGACY_USER_DATABASE_CHECKPOINT_KEY)
                .execute(&mut *connection)
                .await?;
                Ok(())
            }
            .await
        } else {
            Ok(())
        };
        let detach_result = sqlx::query("DETACH DATABASE legacy_user_database")
            .execute(&mut *connection)
            .await;
        match (cleanup_result, checkpoint_result, detach_result) {
            (Ok((rows, checkpoint_performed)), Ok(()), Ok(_)) => {
                if checkpoint_performed {
                    info!(
                        rows,
                        "已核对并清理用户数据库中的旧访问记录，WAL 已执行截断 checkpoint"
                    );
                } else {
                    info!("用户数据库旧访问记录已在先前启动中完成清理");
                }
                Ok(rows)
            }
            (Err(error), _, _) => Err(error),
            (Ok(_), Err(error), _) => Err(error),
            (Ok(_), Ok(()), Err(error)) => Err(error.into()),
        }
    }

    /// Truncates the WAL after an explicit retention purge and reports a busy checkpoint.
    pub async fn checkpoint_wal(&self) -> Result<()> {
        let checkpoint: (i64, i64, i64) = sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&self.pool)
            .await?;
        validate_checkpoint(checkpoint, "访问记录数据库")
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
impl AccessLogRepository for SqliteAccessLogRepository {
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
                "访问记录数据库缺少 access_log_retention_days".to_string(),
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
                "访问记录数据库缺少 access_log_retention_days".to_string(),
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
            "访问记录保留天数必须在 {MIN_ACCESS_LOG_RETENTION_DAYS}..=\
             {MAX_ACCESS_LOG_RETENTION_DAYS} 范围内"
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
            "access_log_retention_days 必须在 {MIN_ACCESS_LOG_RETENTION_DAYS}..=\
             {MAX_ACCESS_LOG_RETENTION_DAYS} 范围内，实际为 {retention_days}"
        )));
    }
    Ok(retention_days)
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

fn validate_checkpoint(
    (busy, log_frames, checkpointed_frames): (i64, i64, i64),
    database: &str,
) -> Result<()> {
    if busy != 0 || log_frames != checkpointed_frames {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "{database} WAL checkpoint 未完成：busy={busy}, log={log_frames}, \
             checkpointed={checkpointed_frames}"
        )));
    }
    Ok(())
}

fn same_database_path(left: &Path, right: &Path) -> Result<bool> {
    if left.try_exists()? && right.try_exists()? {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let left_metadata = fs::metadata(left)?;
            let right_metadata = fs::metadata(right)?;
            if left_metadata.dev() == right_metadata.dev()
                && left_metadata.ino() == right_metadata.ino()
            {
                return Ok(true);
            }
        }
        return Ok(fs::canonicalize(left)? == fs::canonicalize(right)?);
    }
    Ok(absolute_lexical_path(left)? == absolute_lexical_path(right)?)
}

fn absolute_lexical_path(path: &Path) -> Result<PathBuf> {
    use std::path::Component;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
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
fn secure_open_and_set_mode(path: &Path, mode: u32, create: bool) -> io::Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut options = OpenOptions::new();
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
        file.set_permissions(fs::Permissions::from_mode(mode))?;
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

        let access_store =
            SqliteAccessLogRepository::connect(directory.path().join("access.sqlite3"))
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

        let access_store =
            SqliteAccessLogRepository::connect(directory.path().join("access.sqlite3"))
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
}
