use super::*;

impl SqliteUserRepository {
    #[instrument(skip(path), fields(database = %path.as_ref().display()))]
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        Self::connect_with_permissions(path, SqliteFilePermissions::OwnerOnly).await
    }

    /// Opens an already-initialized user database without any write capability.
    ///
    /// This is the only constructor the Proxy process should use. It neither creates
    /// directories/files nor runs migrations/imports, and every SQLite connection has both
    /// `SQLITE_OPEN_READONLY` and `PRAGMA query_only=ON`. Proxy Registry must initialize and migrate
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
                 {schema_version}；请先启动 Proxy Registry 完成迁移"
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
        if schema_version < 6 {
            migrate_key_requests_to_v6(&mut transaction).await?;
        }
        let removed_deprecated_permissions = if schema_version < 7 {
            migrate_permissions_to_v7(&mut transaction).await?
        } else {
            0
        };
        if schema_version < 8 {
            create_v8_proxy_address_tables(&mut transaction).await?;
        }
        if schema_version < 9 {
            migrate_key_requests_to_v9(&mut transaction).await?;
        }
        if schema_version < 10 {
            create_v10_account_disable_audits(&mut transaction).await?;
        }
        if schema_version < 11 {
            create_v11_operation_audits(&mut transaction).await?;
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
            sqlx::query("PRAGMA user_version = 11")
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        if removed_deprecated_permissions != 0 {
            info!(
                profiles = removed_deprecated_permissions,
                "已清理停用的 Agent 原始配置查看权限"
            );
        }
        if revoked_compromised_profiles != 0 {
            warn!(
                profiles = revoked_compromised_profiles,
                "已停用使用公开仓库泄露私钥的 legacy 用户；必须轮换密钥后再启用"
            );
        }
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
    pub(super) fn apply_file_permissions(&self) -> Result<()> {
        let mode = self.file_permissions.unix_mode();
        for path in database_files(&self.path) {
            secure_open_and_set_mode(&path, mode, false)?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub(super) fn apply_file_permissions(&self) -> Result<()> {
        Ok(())
    }
}
