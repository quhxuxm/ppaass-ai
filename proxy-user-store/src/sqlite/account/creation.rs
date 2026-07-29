use super::super::*;

impl SqliteUserRepository {
    #[instrument(
        skip(self, user),
        fields(account_id = %user.account_id, login_name = %user.login_name)
    )]
    pub(super) async fn create_managed_user(&self, user: NewManagedUser) -> Result<ManagedUser> {
        let NewManagedUser {
            account_id,
            login_name,
            password_hash,
            role,
            status,
            display_name,
            email,
            avatar_url,
            profile,
            encrypted_private_key,
            external_identity,
        } = user;
        let account_id = normalize_account_id(&account_id)?;
        let login_name = normalize_username(&login_name)?;
        let password_hash = normalize_password_hash(password_hash)?;
        let display_name =
            normalize_optional_field("display_name", display_name, MAX_DISPLAY_NAME_BYTES)?;
        let email = normalize_optional_field("email", email, MAX_EMAIL_BYTES)?;
        let avatar_url = normalize_optional_field("avatar_url", avatar_url, MAX_AVATAR_URL_BYTES)?;
        let profile = normalize_new_user(profile)?;
        validate_private_key_envelope(&encrypted_private_key)?;
        let external_identity = external_identity
            .map(normalize_external_identity)
            .transpose()?;

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if role == AccountRole::User {
            ensure_user_account_capacity(&mut transaction, self.max_user_accounts).await?;
        }
        ensure_account_identifiers_available(
            &mut transaction,
            &account_id,
            &login_name,
            Some(&profile.username),
        )
        .await?;
        if let Some(identity) = &external_identity {
            ensure_external_identity_available(&mut transaction, identity).await?;
        }

        let timestamp = now();
        insert_profile(&mut transaction, &profile, timestamp).await?;
        sqlx::query(
            "INSERT INTO web_accounts \
             (account_id, login_name, password_hash, role, status, linked_username, \
              display_name, email, avatar_url, auth_version, last_login_at, \
              created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?, ?)",
        )
        .bind(&account_id)
        .bind(&login_name)
        .bind(password_hash)
        .bind(role.as_str())
        .bind(status.as_str())
        .bind(&profile.username)
        .bind(&display_name)
        .bind(&email)
        .bind(&avatar_url)
        .bind(timestamp)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO user_private_keys \
             (username, encrypted_private_key, key_version, updated_at) VALUES (?, ?, 1, ?)",
        )
        .bind(&profile.username)
        .bind(&encrypted_private_key)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
        if let Some(identity) = &external_identity {
            sqlx::query(
                "INSERT INTO external_identities (provider, subject, account_id) VALUES (?, ?, ?)",
            )
            .bind(&identity.provider)
            .bind(&identity.subject)
            .bind(&account_id)
            .execute(&mut *transaction)
            .await?;
        }

        let account = fetch_account_by_id(&mut transaction, &account_id)
            .await?
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema("刚创建的 web_accounts 记录不可见".to_string())
            })?;
        let managed = fetch_managed_for_account(&mut transaction, account).await?;
        transaction.commit().await?;
        info!(
            account_id,
            username = profile.username,
            "托管用户已原子创建"
        );
        Ok(managed)
    }

    #[instrument(
        skip(self, account),
        fields(account_id = %account.account_id, login_name = %account.login_name)
    )]
    pub(super) async fn create_user_account(&self, account: NewUserAccount) -> Result<WebAccount> {
        let NewUserAccount {
            account_id,
            login_name,
            password_hash,
            display_name,
            email,
            avatar_url,
            external_identity,
        } = account;
        let account_id = normalize_account_id(&account_id)?;
        let login_name = normalize_username(&login_name)?;
        let password_hash = normalize_password_hash(password_hash)?;
        let display_name =
            normalize_optional_field("display_name", display_name, MAX_DISPLAY_NAME_BYTES)?;
        let email = normalize_optional_field("email", email, MAX_EMAIL_BYTES)?;
        let avatar_url = normalize_optional_field("avatar_url", avatar_url, MAX_AVATAR_URL_BYTES)?;
        let external_identity = external_identity
            .map(normalize_external_identity)
            .transpose()?;

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        ensure_user_account_capacity(&mut transaction, self.max_user_accounts).await?;
        // 初始密钥审批会把 login_name 直接作为 Proxy username。注册阶段就在同一
        // 写事务中保留该名字，避免 legacy/direct profile 使审批永久冲突。
        ensure_account_identifiers_available(
            &mut transaction,
            &account_id,
            &login_name,
            Some(&login_name),
        )
        .await?;
        if let Some(identity) = &external_identity {
            ensure_external_identity_available(&mut transaction, identity).await?;
        }

        let timestamp = now();
        sqlx::query(
            "INSERT INTO web_accounts \
             (account_id, login_name, password_hash, role, status, linked_username, \
              display_name, email, avatar_url, auth_version, last_login_at, \
              created_at, updated_at) \
             VALUES (?, ?, ?, 'user', 'active', NULL, ?, ?, ?, 1, NULL, ?, ?)",
        )
        .bind(&account_id)
        .bind(&login_name)
        .bind(password_hash)
        .bind(&display_name)
        .bind(&email)
        .bind(&avatar_url)
        .bind(timestamp)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
        if let Some(identity) = &external_identity {
            sqlx::query(
                "INSERT INTO external_identities (provider, subject, account_id) VALUES (?, ?, ?)",
            )
            .bind(&identity.provider)
            .bind(&identity.subject)
            .bind(&account_id)
            .execute(&mut *transaction)
            .await?;
        }
        let account = fetch_account_by_id(&mut transaction, &account_id)
            .await?
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema(
                    "刚创建的普通 web_accounts 记录不可见".to_string(),
                )
            })?;
        transaction.commit().await?;
        info!(account_id, "无 Proxy profile 的普通 Web 账号已创建");
        Ok(account)
    }
}
