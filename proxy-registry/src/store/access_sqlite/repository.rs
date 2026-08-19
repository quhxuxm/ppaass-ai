use super::*;

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
        let query = sqlx::AssertSqlSafe(format!(
            "SELECT {ACCESS_RECORD_SELECT} FROM user_access_records \
             WHERE username = ? AND accessed_at >= ? \
             ORDER BY accessed_at DESC, record_id DESC LIMIT ?"
        ));
        sqlx::query(query)
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

#[async_trait]
impl AccessBatchRepository for SqliteAccessLogRepository {
    #[instrument(
        skip(self, records),
        fields(entry_id, batch_id, record_count = records.len())
    )]
    async fn ingest_access_batch(
        &self,
        entry_id: &str,
        batch_id: &str,
        records: &[NewAccessRecord],
        received_at: i64,
    ) -> Result<bool> {
        let entry_id = validate_batch_identifier("entry_id", entry_id)?;
        let batch_id = validate_batch_identifier("batch_id", batch_id)?;
        if records.is_empty() || records.len() > MAX_ACCESS_BATCH_RECORDS {
            return Err(ValidationError::InvalidAccountField(format!(
                "访问记录批次必须包含 1..={MAX_ACCESS_BATCH_RECORDS} 条记录"
            ))
            .into());
        }
        if received_at < 0 {
            return Err(
                ValidationError::InvalidAccountField("received_at 不能为负数".to_string()).into(),
            );
        }
        let normalized = records
            .iter()
            .map(normalize_new_access_record)
            .collect::<Result<Vec<_>>>()?;

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let inserted = sqlx::query(
            "INSERT INTO proxy_access_ingest_batches \
             (entry_id, batch_id, created_at) VALUES (?, ?, ?) \
             ON CONFLICT(entry_id, batch_id) DO NOTHING",
        )
        .bind(&entry_id)
        .bind(&batch_id)
        .bind(received_at)
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(false);
        }

        for record in &normalized {
            apply_access_record(&mut transaction, record).await?;
        }
        transaction.commit().await?;
        Ok(true)
    }

    async fn purge_access_batches_before(&self, before: i64) -> Result<u64> {
        if before < 0 {
            return Err(
                ValidationError::InvalidAccountField("before 不能为负数".to_string()).into(),
            );
        }
        let result = sqlx::query("DELETE FROM proxy_access_ingest_batches WHERE created_at < ?")
            .bind(before)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

fn validate_batch_identifier(field: &str, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_ACCESS_BATCH_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ValidationError::InvalidAccountField(format!(
            "{field} 必须是 1..={MAX_ACCESS_BATCH_ID_BYTES} 字节的安全标识符"
        ))
        .into());
    }
    Ok(value.to_string())
}

fn normalize_new_access_record(record: &NewAccessRecord) -> Result<NewAccessRecord> {
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
    Ok(NewAccessRecord {
        username,
        protocol: record.protocol,
        target_host,
        target_port: record.target_port,
        accessed_at: record.accessed_at,
    })
}

async fn apply_access_record(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record: &NewAccessRecord,
) -> Result<()> {
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
    .bind(&record.username)
    .bind(record.protocol.as_str())
    .bind(&record.target_host)
    .bind(i64::from(record.target_port))
    .bind(record.accessed_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
