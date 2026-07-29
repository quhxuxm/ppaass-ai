use super::super::*;

impl SqliteUserRepository {
    #[instrument(
        skip(self, request),
        fields(request_id = %request.request_id, account_id = %request.account_id)
    )]
    pub(super) async fn submit_key_generation_request(
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

    pub(super) async fn get_pending_key_generation_request(
        &self,
        account_id: &str,
    ) -> Result<Option<KeyGenerationRequest>> {
        let account_id = normalize_account_id(account_id)?;
        let mut connection = self.pool.acquire().await?;
        fetch_pending_key_request_for_account(&mut connection, &account_id).await
    }

    pub(super) async fn get_key_generation_request(
        &self,
        request_id: &str,
    ) -> Result<Option<KeyGenerationRequest>> {
        let request_id = normalize_request_id(request_id)?;
        let mut connection = self.pool.acquire().await?;
        fetch_key_request_by_id(&mut connection, &request_id).await
    }

    pub(super) async fn list_pending_key_generation_requests(
        &self,
    ) -> Result<Vec<KeyGenerationRequest>> {
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
}
