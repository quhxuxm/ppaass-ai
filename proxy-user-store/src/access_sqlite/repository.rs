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
