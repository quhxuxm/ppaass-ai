use super::*;

impl SqliteUserRepository {
    pub(super) async fn update_last_login(
        &self,
        account_id: &str,
        logged_in_at: i64,
    ) -> Result<()> {
        let account_id = normalize_account_id(account_id)?;
        let result = sqlx::query(
            "UPDATE web_accounts SET last_login_at = ?, updated_at = ? WHERE account_id = ?",
        )
        .bind(logged_in_at)
        .bind(now())
        .bind(&account_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(account_id));
        }
        Ok(())
    }

    pub(super) async fn load_encrypted_private_key(
        &self,
        username: &str,
    ) -> Result<Option<EncryptedPrivateKey>> {
        let username = normalize_username(username)?;
        sqlx::query(
            "SELECT username, encrypted_private_key, key_version, updated_at \
             FROM user_private_keys WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?
        .map(row_to_encrypted_private_key)
        .transpose()
    }

    #[instrument(skip(self, rotation), fields(username = %rotation.username))]
    pub(super) async fn rotate_keypair(&self, rotation: KeyPairRotation) -> Result<UserRecord> {
        let username = normalize_username(&rotation.username)?;
        let actor = AccountActor {
            account_id: normalize_account_id(&rotation.actor.account_id)?,
            login_name: normalize_username(&rotation.actor.login_name)?,
        };
        let supplied_audit_reason = rotation
            .audit_reason
            .as_deref()
            .map(normalize_audit_reason)
            .transpose()?;
        let public_key_pem = normalize_public_key_pem(&rotation.public_key_pem)?;
        validate_private_key_envelope(&rotation.encrypted_private_key)?;
        if rotation.expected_key_version < 1 {
            return Err(ValidationError::InvalidAccountField(
                "expected_key_version 必须大于等于 1".to_string(),
            )
            .into());
        }

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let actor_account = fetch_account_by_id(&mut transaction, &actor.account_id)
            .await?
            .filter(|candidate| {
                candidate.login_name == actor.login_name
                    && candidate.status == AccountStatus::Active
            })
            .ok_or_else(|| UserRepositoryError::NotFound(actor.account_id.clone()))?;
        let actor_is_owner = actor_account.linked_username.as_deref() == Some(username.as_str());
        if actor_account.role != AccountRole::Admin && !actor_is_owner {
            return Err(ValidationError::InvalidAccountField(
                "普通用户只能重生成自己的密钥".to_string(),
            )
            .into());
        }
        let audit_reason = if actor_account.role == AccountRole::Admin {
            Some(supplied_audit_reason.ok_or(ValidationError::EmptyAuditReason)?)
        } else {
            supplied_audit_reason
        };
        let actual: Option<i64> =
            sqlx::query_scalar("SELECT key_version FROM users WHERE username = ?")
                .bind(&username)
                .fetch_optional(&mut *transaction)
                .await?;
        let Some(actual) = actual else {
            return Err(UserRepositoryError::NotFound(username));
        };
        if actual != rotation.expected_key_version {
            return Err(UserRepositoryError::VersionConflict {
                username,
                expected: rotation.expected_key_version,
                actual,
            });
        }
        let new_version = actual.checked_add(1).ok_or_else(|| {
            UserRepositoryError::InvalidSchema("用户 key_version 已溢出".to_string())
        })?;
        let timestamp = now();
        let query = format!(
            "UPDATE users SET public_key_pem = ?, key_version = ?, updated_at = ? \
             WHERE username = ? AND key_version = ? RETURNING {USER_SELECT}"
        );
        let user = sqlx::query(&query)
            .bind(public_key_pem)
            .bind(new_version)
            .bind(timestamp)
            .bind(&username)
            .bind(actual)
            .fetch_optional(&mut *transaction)
            .await?
            .map(row_to_user)
            .transpose()?
            .ok_or_else(|| UserRepositoryError::VersionConflict {
                username: username.clone(),
                expected: rotation.expected_key_version,
                actual,
            })?;

        sqlx::query(
            "INSERT INTO user_private_keys \
             (username, encrypted_private_key, key_version, updated_at) VALUES (?, ?, ?, ?) \
             ON CONFLICT(username) DO UPDATE SET \
                 encrypted_private_key = excluded.encrypted_private_key, \
                 key_version = excluded.key_version, \
                 updated_at = excluded.updated_at",
        )
        .bind(&username)
        .bind(rotation.encrypted_private_key)
        .bind(new_version)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
        let target_account = fetch_account_by_linked_username(&mut transaction, &username).await?;
        insert_audit_event(
            &mut transaction,
            NewAuditEvent {
                action: AuditAction::KeyRegenerated,
                actor_account_id: actor.account_id,
                actor_login_name: actor.login_name,
                target_kind: AuditTargetKind::User,
                target_id: target_account
                    .as_ref()
                    .map(|account| account.account_id.clone())
                    .unwrap_or_else(|| username.clone()),
                target_name: target_account
                    .as_ref()
                    .map(|account| account.login_name.clone())
                    .unwrap_or_else(|| username.clone()),
                context_id: None,
                reason: audit_reason,
                previous_value: Some(actual.to_string()),
                new_value: Some(new_version.to_string()),
                created_at: timestamp,
            },
        )
        .await?;
        if let Some(account) = target_account.as_ref() {
            insert_agent_event(
                &mut transaction,
                PROFILE_CHANGED_EVENT,
                Some(&account.account_id),
                timestamp,
            )
            .await?;
        } else {
            insert_agent_event(&mut transaction, PROFILES_CHANGED_EVENT, None, timestamp).await?;
        }
        transaction.commit().await?;
        info!(username, key_version = new_version, "用户密钥对已轮换");
        Ok(user)
    }
}
