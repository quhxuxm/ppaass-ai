use super::super::*;

impl SqliteUserRepository {
    pub(super) async fn key_encryption_binding(&self) -> Result<KeyEncryptionBinding> {
        let mut transaction = self.pool.begin().await?;
        let verifier =
            sqlx::query_scalar::<_, String>("SELECT value FROM app_metadata WHERE key = ?")
                .bind(KEY_ENCRYPTION_VERIFIER_KEY)
                .fetch_optional(&mut *transaction)
                .await?;
        let sample_private_key = sqlx::query(
            "SELECT username, encrypted_private_key, key_version, updated_at \
             FROM user_private_keys ORDER BY username COLLATE BINARY LIMIT 1",
        )
        .fetch_optional(&mut *transaction)
        .await?
        .map(row_to_encrypted_private_key)
        .transpose()?;
        transaction.commit().await?;
        Ok(KeyEncryptionBinding {
            verifier,
            sample_private_key,
        })
    }

    pub(super) async fn initialize_key_encryption_verifier(
        &self,
        verifier: &str,
    ) -> Result<String> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT INTO app_metadata (key, value) VALUES (?, ?) \
             ON CONFLICT(key) DO NOTHING",
        )
        .bind(KEY_ENCRYPTION_VERIFIER_KEY)
        .bind(verifier)
        .execute(&mut *transaction)
        .await?;
        let actual =
            sqlx::query_scalar::<_, String>("SELECT value FROM app_metadata WHERE key = ?")
                .bind(KEY_ENCRYPTION_VERIFIER_KEY)
                .fetch_one(&mut *transaction)
                .await?;
        transaction.commit().await?;
        Ok(actual)
    }

    #[instrument(skip(self, admin), fields(login_name = %admin.login_name))]
    pub(super) async fn bootstrap_admin_if_absent(
        &self,
        admin: NewAdminAccount,
    ) -> Result<BootstrapOutcome> {
        let account_id = normalize_account_id(&admin.account_id)?;
        let login_name = normalize_username(&admin.login_name)?;
        let password_hash = normalize_password_hash(admin.password_hash)?;
        let display_name =
            normalize_optional_field("display_name", admin.display_name, MAX_DISPLAY_NAME_BYTES)?;
        let email = normalize_optional_field("email", admin.email, MAX_EMAIL_BYTES)?;
        let avatar_url =
            normalize_optional_field("avatar_url", admin.avatar_url, MAX_AVATAR_URL_BYTES)?;

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let login_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM web_accounts WHERE login_name = ?)")
                .bind(&login_name)
                .fetch_one(&mut *transaction)
                .await?;
        if login_exists {
            transaction.rollback().await?;
            return Ok(BootstrapOutcome::AlreadyExists);
        }
        ensure_account_identifiers_available(&mut transaction, &account_id, &login_name, None)
            .await?;

        let timestamp = now();
        sqlx::query(
            "INSERT INTO web_accounts \
             (account_id, login_name, password_hash, role, status, linked_username, \
              display_name, email, avatar_url, auth_version, last_login_at, \
              created_at, updated_at) \
             VALUES (?, ?, ?, 'admin', 'active', NULL, ?, ?, ?, 1, NULL, ?, ?)",
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
        let account = WebAccount {
            account_id,
            login_name,
            role: AccountRole::Admin,
            status: AccountStatus::Active,
            linked_username: None,
            display_name,
            email,
            avatar_url,
            auth_version: 1,
            last_login_at: None,
            created_at: timestamp,
            updated_at: timestamp,
        };
        transaction.commit().await?;
        info!(account_id = account.account_id, "首个 Web 管理员已创建");
        Ok(BootstrapOutcome::Created(account))
    }

    pub(super) async fn get_account_by_login(
        &self,
        login_name: &str,
    ) -> Result<Option<WebAccount>> {
        let login_name = normalize_username(login_name)?;
        let mut connection = self.pool.acquire().await?;
        fetch_account_by_login(&mut connection, &login_name).await
    }

    pub(super) async fn get_account_by_id(&self, account_id: &str) -> Result<Option<WebAccount>> {
        let account_id = normalize_account_id(account_id)?;
        let mut connection = self.pool.acquire().await?;
        fetch_account_by_id(&mut connection, &account_id).await
    }

    pub(super) async fn get_account_by_external(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<WebAccount>> {
        let provider = normalize_provider(provider)?;
        let subject = normalize_provider_subject(subject)?;
        let query = format!(
            "SELECT {QUALIFIED_ACCOUNT_SELECT} FROM web_accounts a \
             INNER JOIN external_identities i ON i.account_id = a.account_id \
             WHERE i.provider = ? AND i.subject = ?"
        );
        sqlx::query(&query)
            .bind(provider)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await?
            .map(row_to_account)
            .transpose()
    }

    pub(super) async fn get_login_record(&self, login_name: &str) -> Result<Option<LoginRecord>> {
        let login_name = normalize_username(login_name)?;
        let query = format!(
            "SELECT {ACCOUNT_SELECT}, password_hash FROM web_accounts WHERE login_name = ?"
        );
        let row = sqlx::query(&query)
            .bind(login_name)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            let password_hash = row.try_get("password_hash")?;
            Ok(LoginRecord {
                account: row_to_account(row)?,
                password_hash,
            })
        })
        .transpose()
    }

    pub(super) async fn list_managed_users(&self) -> Result<Vec<ManagedUser>> {
        let mut connection = self.pool.acquire().await?;
        let account_query =
            format!("SELECT {ACCOUNT_SELECT} FROM web_accounts ORDER BY login_name COLLATE BINARY");
        let accounts = sqlx::query(&account_query)
            .fetch_all(&mut *connection)
            .await?
            .into_iter()
            .map(row_to_account)
            .collect::<Result<Vec<_>>>()?;
        let mut users = Vec::with_capacity(accounts.len());
        for account in accounts {
            users.push(fetch_managed_for_account(&mut connection, account).await?);
        }

        let legacy_query = format!(
            "SELECT {USER_SELECT} FROM users u \
             WHERE NOT EXISTS (\
                 SELECT 1 FROM web_accounts a WHERE a.linked_username = u.username\
             ) ORDER BY u.username COLLATE BINARY"
        );
        let profiles = sqlx::query(&legacy_query)
            .fetch_all(&mut *connection)
            .await?
            .into_iter()
            .map(row_to_user)
            .collect::<Result<Vec<_>>>()?;
        for profile in profiles {
            let has_private_key: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM user_private_keys WHERE username = ?)",
            )
            .bind(&profile.username)
            .fetch_one(&mut *connection)
            .await?;
            users.push(ManagedUser {
                account: None,
                profile: Some(profile),
                has_private_key,
                providers: Vec::new(),
                assigned_proxy_addresses: Vec::new(),
                selected_proxy_address: None,
            });
        }
        Ok(users)
    }

    pub(super) async fn get_managed_user(&self, account_id: &str) -> Result<Option<ManagedUser>> {
        let account_id = normalize_account_id(account_id)?;
        let mut connection = self.pool.acquire().await?;
        let Some(account) = fetch_account_by_id(&mut connection, &account_id).await? else {
            return Ok(None);
        };
        fetch_managed_for_account(&mut connection, account)
            .await
            .map(Some)
    }

    pub(super) async fn get_managed_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<ManagedUser>> {
        let username = normalize_username(username)?;
        let mut connection = self.pool.acquire().await?;
        let Some(profile) = fetch_profile(&mut connection, &username).await? else {
            return Ok(None);
        };
        let account_query =
            format!("SELECT {ACCOUNT_SELECT} FROM web_accounts WHERE linked_username = ?");
        let account = sqlx::query(&account_query)
            .bind(&username)
            .fetch_optional(&mut *connection)
            .await?
            .map(row_to_account)
            .transpose()?;
        if let Some(account) = account {
            fetch_managed_for_account(&mut connection, account)
                .await
                .map(Some)
        } else {
            let has_private_key: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM user_private_keys WHERE username = ?)",
            )
            .bind(&username)
            .fetch_one(&mut *connection)
            .await?;
            Ok(Some(ManagedUser {
                account: None,
                profile: Some(profile),
                has_private_key,
                providers: Vec::new(),
                assigned_proxy_addresses: Vec::new(),
                selected_proxy_address: None,
            }))
        }
    }
}
