use super::super::*;

impl SqliteUserRepository {
    #[instrument(skip(self, update), fields(account_id))]
    pub(super) async fn update_managed_user(
        &self,
        account_id: &str,
        update: ManagedUserUpdate,
    ) -> Result<ManagedUser> {
        let account_id = normalize_account_id(account_id)?;
        if update.is_empty() {
            return Err(ValidationError::EmptyUpdate.into());
        }
        let permissions = update
            .permissions
            .as_deref()
            .map(normalize_permissions)
            .transpose()?;
        let proxy_address_ids = update
            .proxy_address_ids
            .as_deref()
            .map(normalize_proxy_address_ids)
            .transpose()?;
        let display_name = update
            .display_name
            .map(|value| {
                value
                    .map(|value| normalize_field("display_name", &value, MAX_DISPLAY_NAME_BYTES))
                    .transpose()
            })
            .transpose()?;
        let email = update
            .email
            .map(|value| {
                value
                    .map(|value| normalize_field("email", &value, MAX_EMAIL_BYTES))
                    .transpose()
            })
            .transpose()?;
        let avatar_url = update
            .avatar_url
            .map(|value| {
                value
                    .map(|value| normalize_field("avatar_url", &value, MAX_AVATAR_URL_BYTES))
                    .transpose()
            })
            .transpose()?;
        let disabled_by = update
            .disabled_by
            .map(|actor| {
                Ok::<_, UserRepositoryError>(AccountActor {
                    account_id: normalize_account_id(&actor.account_id)?,
                    login_name: normalize_username(&actor.login_name)?,
                })
            })
            .transpose()?;
        if disabled_by.is_some() && update.status != Some(AccountStatus::Disabled) {
            return Err(ValidationError::InvalidAccountField(
                "disabled_by 只能用于停用账号".to_string(),
            )
            .into());
        }

        let profile_update_requested =
            update.enabled.is_some() || permissions.is_some() || update.expires_at.is_some();
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let Some(mut account) = fetch_account_by_id(&mut transaction, &account_id).await? else {
            return Err(UserRepositoryError::NotFound(account_id));
        };
        let target_role = update.role.unwrap_or(account.role);
        let target_status = update.status.unwrap_or(account.status);
        guard_root_admin(&account, Some(target_role), Some(target_status))?;
        let newly_disabled =
            account.status != AccountStatus::Disabled && target_status == AccountStatus::Disabled;
        if newly_disabled {
            if let Some(actor) = disabled_by.as_ref() {
                let reviewer = fetch_account_by_id(&mut transaction, &actor.account_id)
                    .await?
                    .filter(|candidate| {
                        candidate.login_name == actor.login_name
                            && candidate.role == AccountRole::Admin
                            && candidate.status == AccountStatus::Active
                    })
                    .ok_or_else(|| UserRepositoryError::ReviewerNotActiveAdmin {
                        account_id: actor.account_id.clone(),
                    })?;
                debug_assert_eq!(reviewer.login_name, actor.login_name);
            }
        }

        let mut profile = match account.linked_username.as_deref() {
            Some(username) => fetch_profile(&mut transaction, username).await?,
            None => None,
        };
        if profile_update_requested && profile.is_none() {
            return Err(UserRepositoryError::NotFound(format!(
                "账号 {} 未关联 Proxy 用户",
                account.account_id
            )));
        }

        let auth_changed = account.role != target_role || account.status != target_status;
        account.role = target_role;
        account.status = target_status;
        if let Some(display_name) = display_name {
            account.display_name = display_name;
        }
        if let Some(email) = email {
            account.email = email;
        }
        if let Some(avatar_url) = avatar_url {
            account.avatar_url = avatar_url;
        }
        if auth_changed {
            account.auth_version = account.auth_version.checked_add(1).ok_or_else(|| {
                UserRepositoryError::InvalidSchema(format!(
                    "账号 {} 的 auth_version 已溢出",
                    account.account_id
                ))
            })?;
        }
        account.updated_at = now();
        sqlx::query(
            "UPDATE web_accounts SET role = ?, status = ?, display_name = ?, email = ?, \
             avatar_url = ?, auth_version = ?, updated_at = ? WHERE account_id = ?",
        )
        .bind(account.role.as_str())
        .bind(account.status.as_str())
        .bind(&account.display_name)
        .bind(&account.email)
        .bind(&account.avatar_url)
        .bind(account.auth_version)
        .bind(account.updated_at)
        .bind(&account.account_id)
        .execute(&mut *transaction)
        .await?;
        if newly_disabled && let Some(actor) = disabled_by {
            sqlx::query(
                "INSERT INTO account_disable_audits \
                 (target_account_id, target_login_name, admin_account_id, \
                  admin_login_name, disabled_at) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&account.account_id)
            .bind(&account.login_name)
            .bind(actor.account_id)
            .bind(actor.login_name)
            .bind(account.updated_at)
            .execute(&mut *transaction)
            .await?;
        }

        if let Some(profile) = profile.as_mut() {
            if let Some(enabled) = update.enabled {
                profile.enabled = enabled;
            }
            if let Some(permissions) = permissions {
                profile.permissions = permissions;
            }
            if let Some(expires_at) = update.expires_at {
                profile.expires_at = expires_at;
            }
            if profile_update_requested {
                profile.updated_at = now();
                sqlx::query(
                    "UPDATE users SET permissions = ?, enabled = ?, expires_at = ?, \
                     updated_at = ? WHERE username = ?",
                )
                .bind(encode_permissions(&profile.permissions))
                .bind(profile.enabled)
                .bind(profile.expires_at)
                .bind(profile.updated_at)
                .bind(&profile.username)
                .execute(&mut *transaction)
                .await?;
            }
        }
        if let Some(proxy_address_ids) = proxy_address_ids {
            replace_account_proxy_addresses(
                &mut transaction,
                &account.account_id,
                &proxy_address_ids,
                now(),
            )
            .await?;
        }

        let managed = fetch_managed_for_account(&mut transaction, account).await?;
        transaction.commit().await?;
        info!(account_id, "托管用户配置已更新");
        Ok(managed)
    }

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
        let public_key_pem = normalize_public_key_pem(&rotation.public_key_pem)?;
        validate_private_key_envelope(&rotation.encrypted_private_key)?;
        if rotation.expected_key_version < 1 {
            return Err(ValidationError::InvalidAccountField(
                "expected_key_version 必须大于等于 1".to_string(),
            )
            .into());
        }

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
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

        // UPSERT 是有意的：历史 legacy 用户可能没有私钥记录，也应能轮换。
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
        transaction.commit().await?;
        info!(username, key_version = new_version, "用户密钥对已轮换");
        Ok(user)
    }
}
