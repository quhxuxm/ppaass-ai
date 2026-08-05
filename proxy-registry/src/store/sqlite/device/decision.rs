use super::super::*;

impl SqliteUserRepository {
    #[instrument(skip(self, user_code_hash), fields(account_id, account_auth_version))]
    pub(super) async fn authorize_agent_device(
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
    pub(super) async fn deny_agent_device(
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
}
