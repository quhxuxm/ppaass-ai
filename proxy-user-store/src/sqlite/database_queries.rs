use super::*;

pub(super) async fn insert_profile(
    transaction: &mut Transaction<'_, Sqlite>,
    profile: &NewUser,
    timestamp: i64,
) -> Result<()> {
    let result = sqlx::query(
        "INSERT INTO users \
         (username, public_key_pem, permissions, enabled, origin, key_version, \
          expires_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?) ON CONFLICT(username) DO NOTHING",
    )
    .bind(&profile.username)
    .bind(&profile.public_key_pem)
    .bind(encode_permissions(&profile.permissions))
    .bind(profile.enabled)
    .bind(profile.origin.as_str())
    .bind(profile.expires_at)
    .bind(timestamp)
    .bind(timestamp)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 0 {
        return Err(UserRepositoryError::Conflict(profile.username.clone()));
    }
    Ok(())
}

pub(super) async fn ensure_account_identifiers_available(
    transaction: &mut Transaction<'_, Sqlite>,
    account_id: &str,
    login_name: &str,
    linked_username: Option<&str>,
) -> Result<()> {
    let account_id_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM web_accounts WHERE account_id = ?)")
            .bind(account_id)
            .fetch_one(&mut **transaction)
            .await?;
    if account_id_exists {
        return Err(UserRepositoryError::Conflict(account_id.to_string()));
    }
    let login_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM web_accounts WHERE login_name = ?)")
            .bind(login_name)
            .fetch_one(&mut **transaction)
            .await?;
    if login_exists {
        return Err(UserRepositoryError::Conflict(login_name.to_string()));
    }
    if let Some(username) = linked_username {
        let profile_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)")
                .bind(username)
                .fetch_one(&mut **transaction)
                .await?;
        if profile_exists {
            return Err(UserRepositoryError::Conflict(username.to_string()));
        }
    }
    Ok(())
}

pub(super) async fn ensure_external_identity_available(
    transaction: &mut Transaction<'_, Sqlite>,
    identity: &ExternalIdentity,
) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM external_identities WHERE provider = ? AND subject = ?)",
    )
    .bind(&identity.provider)
    .bind(&identity.subject)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        return Err(UserRepositoryError::ExternalIdentityConflict {
            provider: identity.provider.clone(),
            subject: identity.subject.clone(),
        });
    }
    Ok(())
}

pub(super) fn guard_root_admin(
    current: &WebAccount,
    target_role: Option<AccountRole>,
    target_status: Option<AccountStatus>,
) -> Result<()> {
    if current.login_name != "admin" {
        return Ok(());
    }
    if target_role == Some(AccountRole::Admin) && target_status == Some(AccountStatus::Active) {
        Ok(())
    } else {
        Err(UserRepositoryError::RootAdminProtected)
    }
}

pub(super) async fn fetch_account_by_id(
    connection: &mut SqliteConnection,
    account_id: &str,
) -> Result<Option<WebAccount>> {
    let query = format!("SELECT {ACCOUNT_SELECT} FROM web_accounts WHERE account_id = ?");
    sqlx::query(&query)
        .bind(account_id)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_account)
        .transpose()
}

pub(super) async fn fetch_account_by_login(
    connection: &mut SqliteConnection,
    login_name: &str,
) -> Result<Option<WebAccount>> {
    let query = format!("SELECT {ACCOUNT_SELECT} FROM web_accounts WHERE login_name = ?");
    sqlx::query(&query)
        .bind(login_name)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_account)
        .transpose()
}

pub(super) async fn fetch_key_request_by_id(
    connection: &mut SqliteConnection,
    request_id: &str,
) -> Result<Option<KeyGenerationRequest>> {
    let query =
        format!("SELECT {KEY_REQUEST_SELECT} FROM key_generation_requests WHERE request_id = ?");
    sqlx::query(&query)
        .bind(request_id)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_key_request)
        .transpose()
}

pub(super) async fn fetch_pending_key_request_for_account(
    connection: &mut SqliteConnection,
    account_id: &str,
) -> Result<Option<KeyGenerationRequest>> {
    let query = format!(
        "SELECT {KEY_REQUEST_SELECT} FROM key_generation_requests \
         WHERE account_id = ? AND status = 'pending' LIMIT 1"
    );
    sqlx::query(&query)
        .bind(account_id)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_key_request)
        .transpose()
}

pub(super) async fn fetch_agent_device_authorization_by_user_code(
    connection: &mut SqliteConnection,
    user_code_hash: &str,
) -> Result<Option<AgentDeviceAuthorization>> {
    let query = format!(
        "SELECT {DEVICE_AUTHORIZATION_SELECT} FROM agent_device_authorizations \
         WHERE user_code_hash = ?"
    );
    sqlx::query(&query)
        .bind(user_code_hash)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_agent_device_authorization)
        .transpose()
}

pub(super) async fn fetch_profile(
    connection: &mut SqliteConnection,
    username: &str,
) -> Result<Option<UserRecord>> {
    let query = format!("SELECT {USER_SELECT} FROM users WHERE username = ?");
    sqlx::query(&query)
        .bind(username)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_user)
        .transpose()
}

pub(super) async fn fetch_managed_for_account(
    connection: &mut SqliteConnection,
    account: WebAccount,
) -> Result<ManagedUser> {
    let profile = match account.linked_username.as_deref() {
        Some(username) => Some(fetch_profile(connection, username).await?.ok_or_else(|| {
            UserRepositoryError::InvalidSchema(format!(
                "账号 {} 关联的用户 {username} 不存在",
                account.account_id
            ))
        })?),
        None => None,
    };
    let has_private_key = if let Some(profile) = &profile {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_private_keys WHERE username = ?)")
            .bind(&profile.username)
            .fetch_one(&mut *connection)
            .await?
    } else {
        false
    };
    let providers = sqlx::query(
        "SELECT provider, subject FROM external_identities \
         WHERE account_id = ? ORDER BY provider COLLATE BINARY, subject COLLATE BINARY",
    )
    .bind(&account.account_id)
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .map(|row| {
        Ok(ExternalIdentity {
            provider: row.try_get("provider")?,
            subject: row.try_get("subject")?,
        })
    })
    .collect::<Result<Vec<_>>>()?;
    Ok(ManagedUser {
        account: Some(account),
        profile,
        has_private_key,
        providers,
    })
}
