use super::super::*;

impl SqliteUserRepository {
    #[instrument(skip(self, authorization))]
    pub(super) async fn create_agent_device_authorization(
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

    pub(super) async fn get_agent_device_authorization_by_user_code(
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
        let query = sqlx::AssertSqlSafe(format!(
            "SELECT {DEVICE_AUTHORIZATION_SELECT} FROM agent_device_authorizations \
             WHERE user_code_hash = ?"
        ));
        sqlx::query(query)
            .bind(user_code_hash)
            .fetch_optional(&self.pool)
            .await?
            .map(row_to_agent_device_authorization)
            .transpose()
    }
}
