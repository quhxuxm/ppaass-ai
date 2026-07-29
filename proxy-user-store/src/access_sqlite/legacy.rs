use super::*;

impl SqliteAccessLogRepository {
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
}
