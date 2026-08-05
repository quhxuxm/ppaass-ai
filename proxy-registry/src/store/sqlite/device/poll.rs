use super::super::*;

impl SqliteUserRepository {
    #[instrument(skip(self, device_code_hash))]
    pub(super) async fn poll_agent_device_authorization(
        &self,
        device_code_hash: &str,
        now: i64,
    ) -> Result<AgentDeviceAuthorizationPoll> {
        let device_code_hash = normalize_code_hash("device_code_hash", device_code_hash)?;
        if now < 0 {
            return Err(
                ValidationError::InvalidAccountField("设备授权轮询参数无效".to_string()).into(),
            );
        }
        let query = format!(
            "SELECT {DEVICE_AUTHORIZATION_SELECT} FROM agent_device_authorizations \
             WHERE device_code_hash = ?"
        );
        let record = sqlx::query(&query)
            .bind(&device_code_hash)
            .fetch_optional(&self.pool)
            .await?
            .map(row_to_agent_device_authorization)
            .transpose()?;
        let Some(record) = record else {
            return Ok(AgentDeviceAuthorizationPoll::NotFound);
        };
        if let Some(result) = non_pending_device_authorization_poll(&record, now)? {
            return Ok(result);
        }
        Ok(AgentDeviceAuthorizationPoll::Pending)
    }

    #[instrument(
        skip(self, claim),
        fields(
            account_id = %claim.account_id,
            account_auth_version = claim.account_auth_version
        )
    )]
    pub(super) async fn finalize_agent_device_authorization(
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
                     AND account.role IN ('user', 'admin') \
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
