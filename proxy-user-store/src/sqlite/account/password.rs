use super::super::*;

impl SqliteUserRepository {
    #[instrument(skip(self, password_hash), fields(account_id))]
    pub(super) async fn update_password_hash(
        &self,
        account_id: &str,
        expected_auth_version: i64,
        password_hash: String,
    ) -> Result<WebAccount> {
        let account_id = normalize_account_id(account_id)?;
        let password_hash = normalize_password_hash(Some(password_hash))?.ok_or_else(|| {
            ValidationError::InvalidAccountField("password_hash 不能为空".to_string())
        })?;
        let next_auth_version = expected_auth_version.checked_add(1).ok_or_else(|| {
            UserRepositoryError::InvalidSchema(format!("账号 {account_id} 的 auth_version 已溢出"))
        })?;
        if expected_auth_version < 1 {
            return Err(ValidationError::InvalidAccountField(
                "expected_auth_version 必须大于等于 1".to_string(),
            )
            .into());
        }

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let query = format!(
            "UPDATE web_accounts SET password_hash = ?, auth_version = ?, updated_at = ? \
             WHERE account_id = ? AND auth_version = ? RETURNING {ACCOUNT_SELECT}"
        );
        let updated_at = now();
        let account = sqlx::query(&query)
            .bind(password_hash)
            .bind(next_auth_version)
            .bind(updated_at)
            .bind(&account_id)
            .bind(expected_auth_version)
            .fetch_optional(&mut *transaction)
            .await?
            .map(row_to_account)
            .transpose()?;
        let account = match account {
            Some(account) => account,
            None => {
                let Some(current) = fetch_account_by_id(&mut transaction, &account_id).await?
                else {
                    return Err(UserRepositoryError::NotFound(account_id));
                };
                return Err(UserRepositoryError::AccountVersionConflict {
                    account_id,
                    expected: expected_auth_version,
                    actual: current.auth_version,
                });
            }
        };
        transaction.commit().await?;
        info!(
            account_id = account.account_id,
            auth_version = account.auth_version,
            "账号密码哈希已更新"
        );
        Ok(account)
    }
}
