use super::super::*;

impl SqliteUserRepository {
    #[instrument(skip(self), fields(request_id, reviewer_account_id))]
    pub(super) async fn reject_key_generation_request(
        &self,
        request_id: &str,
        reviewer_account_id: &str,
    ) -> Result<KeyGenerationRequest> {
        let request_id = normalize_request_id(request_id)?;
        let reviewer_account_id = normalize_account_id(reviewer_account_id)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let request = fetch_key_request_by_id(&mut transaction, &request_id)
            .await?
            .ok_or_else(|| UserRepositoryError::KeyRequestNotFound(request_id.clone()))?;
        if request.status != KeyRequestStatus::Pending {
            return Err(UserRepositoryError::KeyRequestAlreadyReviewed {
                request_id,
                status: request.status,
            });
        }
        let reviewer = fetch_account_by_id(&mut transaction, &reviewer_account_id)
            .await?
            .ok_or_else(|| UserRepositoryError::NotFound(reviewer_account_id.clone()))?;
        ensure_active_admin(&reviewer)?;
        let timestamp = now();
        let result = sqlx::query(
            "UPDATE key_generation_requests SET status = 'rejected', \
             reviewer_account_id = ?, reviewed_at = ? \
             WHERE request_id = ? AND status = 'pending'",
        )
        .bind(&reviewer.account_id)
        .bind(timestamp)
        .bind(&request.request_id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(UserRepositoryError::KeyRequestAlreadyReviewed {
                request_id: request.request_id,
                status: KeyRequestStatus::Pending,
            });
        }
        let request = fetch_key_request_by_id(&mut transaction, &request_id)
            .await?
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema(
                    "刚拒绝的 key_generation_requests 记录不可见".to_string(),
                )
            })?;
        transaction.commit().await?;
        info!(
            request_id,
            reviewer_account_id,
            account_id = request.account_id,
            kind = request.kind.as_str(),
            "管理员已拒绝密钥申请"
        );
        Ok(request)
    }

    #[instrument(skip(self), fields(account_id))]
    pub(super) async fn delete_managed_user(&self, account_id: &str) -> Result<()> {
        let account_id = normalize_account_id(account_id)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let Some(account) = fetch_account_by_id(&mut transaction, &account_id).await? else {
            return Err(UserRepositoryError::NotFound(account_id));
        };
        guard_last_admin(&mut transaction, &account, None, None).await?;

        sqlx::query("DELETE FROM web_accounts WHERE account_id = ?")
            .bind(&account.account_id)
            .execute(&mut *transaction)
            .await?;
        if let Some(username) = &account.linked_username {
            sqlx::query("DELETE FROM users WHERE username = ?")
                .bind(username)
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        info!(account_id, "托管用户已删除");
        Ok(())
    }

    pub(super) async fn active_admin_count(&self) -> Result<u64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM web_accounts WHERE role = 'admin' AND status = 'active'",
        )
        .fetch_one(&self.pool)
        .await?;
        u64::try_from(count)
            .map_err(|_| UserRepositoryError::InvalidSchema("管理员数量不能表示为 u64".to_string()))
    }
}
