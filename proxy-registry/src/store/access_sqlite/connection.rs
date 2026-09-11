use super::*;

const SQLITE_PRAGMA_SECURE_DELETE:&str="secure_delete";
const SQLITE_PRAGMA_JOURNAL_SIZE_LIMIT:&str="journal_size_limit";
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
            .pragma(SQLITE_PRAGMA_SECURE_DELETE, "ON")
            .pragma(SQLITE_PRAGMA_JOURNAL_SIZE_LIMIT, "0");
        // Multiple Proxy Registry processes keep this WAL database open. SQLx's
        // default 10-minute idle timeout and 30-minute maximum lifetime briefly close and
        // replace pooled connections. On Unix that can let SQLite unlink/recreate `-wal` and
        // `-shm` while the other long-lived process still has the previous files open, leaving
        // the reader on stale sidecar inodes. Access operations are short and SQLite serializes
        // writes anyway, so one non-recycled connection per process is sufficient and keeps
        // the shared WAL identity stable during routine long-running service operation.
        let pool = access_pool_options()
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

    #[doc(hidden)]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
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
        }
        if schema_version < 2 {
            sqlx::query(
                r#"
                CREATE TABLE proxy_access_ingest_batches (
                    entry_id TEXT COLLATE BINARY NOT NULL,
                    batch_id TEXT COLLATE BINARY NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY(entry_id, batch_id)
                )
                "#,
            )
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "CREATE INDEX idx_access_ingest_batches_time \
                 ON proxy_access_ingest_batches(created_at)",
            )
            .execute(&mut *transaction)
            .await?;
        }
        if schema_version < ACCESS_LOG_SCHEMA_VERSION {
            sqlx::query("PRAGMA user_version = 2")
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
        sqlx::query(
            "SELECT entry_id, batch_id, created_at \
             FROM proxy_access_ingest_batches LIMIT 0",
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
}

#[doc(hidden)]
pub fn access_pool_options() -> SqlitePoolOptions {
    SqlitePoolOptions::new()
        .min_connections(1)
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
}
