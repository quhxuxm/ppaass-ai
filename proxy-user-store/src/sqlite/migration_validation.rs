use super::*;

pub(super) async fn revoke_compromised_bundled_demo_profiles(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<u64> {
    let result = sqlx::query(
        "UPDATE users \
         SET enabled = 0, \
             key_version = CASE \
                 WHEN key_version < 9223372036854775807 THEN key_version + 1 \
                 ELSE key_version \
             END, \
             updated_at = ? \
         WHERE origin = 'legacy' AND enabled = 1 \
           AND public_key_pem IN (?, ?)",
    )
    .bind(now())
    .bind(COMPROMISED_BUNDLED_DEMO_PUBLIC_KEYS[0])
    .bind(COMPROMISED_BUNDLED_DEMO_PUBLIC_KEYS[1])
    .execute(&mut **transaction)
    .await?;
    Ok(result.rows_affected())
}

pub(super) async fn ensure_user_account_capacity(
    transaction: &mut Transaction<'_, Sqlite>,
    max_user_accounts: i64,
) -> Result<()> {
    let account_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM web_accounts WHERE role = 'user'")
            .fetch_one(&mut **transaction)
            .await?;
    if account_count >= max_user_accounts {
        return Err(UserRepositoryError::UserAccountCapacity);
    }
    Ok(())
}

pub(super) async fn validate_schema(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    require_columns(
        transaction,
        "users",
        &[
            "username",
            "public_key_pem",
            "permissions",
            "enabled",
            "origin",
            "key_version",
            "expires_at",
            "created_at",
            "updated_at",
        ],
    )
    .await?;
    require_columns(transaction, "app_metadata", &["key", "value"]).await?;
    require_columns(
        transaction,
        "web_accounts",
        &[
            "account_id",
            "login_name",
            "password_hash",
            "role",
            "status",
            "linked_username",
            "display_name",
            "email",
            "avatar_url",
            "auth_version",
            "last_login_at",
            "created_at",
            "updated_at",
        ],
    )
    .await?;
    require_columns(
        transaction,
        "external_identities",
        &["provider", "subject", "account_id"],
    )
    .await?;
    require_columns(
        transaction,
        "user_private_keys",
        &[
            "username",
            "encrypted_private_key",
            "key_version",
            "updated_at",
        ],
    )
    .await?;
    require_columns(
        transaction,
        "key_generation_requests",
        &[
            "request_id",
            "account_id",
            "kind",
            "status",
            "expected_key_version",
            "reviewer_account_id",
            "requested_at",
            "reviewed_at",
            "approved_expires_at",
            "request_message",
        ],
    )
    .await?;
    require_columns(
        transaction,
        "user_access_records",
        &[
            "record_id",
            "username",
            "protocol",
            "target_host",
            "target_port",
            "access_count",
            "accessed_at",
        ],
    )
    .await?;
    require_columns(
        transaction,
        "agent_device_authorizations",
        &[
            "device_code_hash",
            "user_code_hash",
            "client_name",
            "platform",
            "status",
            "authorized_account_id",
            "authorized_auth_version",
            "created_at",
            "expires_at",
            "authorized_at",
            "consumed_at",
            "last_polled_at",
        ],
    )
    .await?;
    require_columns(
        transaction,
        "proxy_addresses",
        &[
            "proxy_address_id",
            "label",
            "address",
            "enabled",
            "created_at",
            "updated_at",
        ],
    )
    .await?;
    require_columns(
        transaction,
        "account_proxy_addresses",
        &["account_id", "proxy_address_id", "assigned_at"],
    )
    .await?;
    let retention_days: Option<String> =
        sqlx::query_scalar("SELECT value FROM app_metadata WHERE key = ?")
            .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
            .fetch_optional(&mut **transaction)
            .await?;
    let Some(retention_days) = retention_days else {
        return Err(UserRepositoryError::InvalidSchema(
            "app_metadata 缺少 access_log_retention_days".to_string(),
        ));
    };
    parse_retention_days(&retention_days).map(|_| ())
}

pub(super) async fn require_columns(
    transaction: &mut Transaction<'_, Sqlite>,
    table: &str,
    required: &[&str],
) -> Result<()> {
    let columns = table_columns(transaction, table).await?;
    if columns.is_empty() {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "{table} 表不存在或没有字段"
        )));
    }
    for required in required {
        if !columns.iter().any(|column| column == required) {
            return Err(UserRepositoryError::InvalidSchema(format!(
                "{table} 表缺少字段 {required}"
            )));
        }
    }
    Ok(())
}

pub(super) async fn table_columns(
    transaction: &mut Transaction<'_, Sqlite>,
    table: &str,
) -> Result<Vec<String>> {
    // table 只来自本文件中的常量，不接受外部输入。
    let query = format!("PRAGMA table_info({table})");
    sqlx::query(&query)
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|row| row.try_get("name"))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}
