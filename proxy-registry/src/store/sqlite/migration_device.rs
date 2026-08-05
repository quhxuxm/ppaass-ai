use super::*;

pub(super) async fn create_v5_tables(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE agent_device_authorizations (
            device_code_hash TEXT COLLATE BINARY NOT NULL PRIMARY KEY
                CHECK(length(device_code_hash) = 43),
            user_code_hash TEXT COLLATE BINARY NOT NULL UNIQUE
                CHECK(length(user_code_hash) = 43),
            client_name TEXT NOT NULL
                CHECK(length(client_name) > 0 AND length(client_name) <= 128),
            platform TEXT NOT NULL
                CHECK(length(platform) > 0 AND length(platform) <= 32),
            status TEXT NOT NULL
                CHECK(status IN ('pending', 'authorized', 'denied', 'consumed')),
            authorized_account_id TEXT COLLATE BINARY,
            authorized_auth_version INTEGER
                CHECK(authorized_auth_version IS NULL OR authorized_auth_version >= 1),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
            authorized_at INTEGER,
            consumed_at INTEGER,
            last_polled_at INTEGER,
            FOREIGN KEY(authorized_account_id) REFERENCES web_accounts(account_id)
                ON DELETE CASCADE,
            CHECK (
                (status = 'pending' AND authorized_account_id IS NULL
                    AND authorized_auth_version IS NULL AND authorized_at IS NULL
                    AND consumed_at IS NULL) OR
                (status = 'authorized' AND authorized_account_id IS NOT NULL
                    AND authorized_auth_version IS NOT NULL AND authorized_at IS NOT NULL
                    AND consumed_at IS NULL) OR
                (status = 'denied' AND authorized_account_id IS NOT NULL
                    AND authorized_auth_version IS NULL AND authorized_at IS NOT NULL
                    AND consumed_at IS NULL) OR
                (status = 'consumed' AND authorized_account_id IS NOT NULL
                    AND authorized_auth_version IS NOT NULL AND authorized_at IS NOT NULL
                    AND consumed_at IS NOT NULL)
            )
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_agent_device_authorizations_expiry \
         ON agent_device_authorizations(expires_at)",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) async fn ensure_v5_indexes(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_web_accounts_role \
         ON web_accounts(role)",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_agent_device_authorizations_active_expiry \
         ON agent_device_authorizations(expires_at) \
         WHERE status IN ('pending', 'authorized')",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
