use super::*;

pub(super) async fn create_v3_tables(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    // v2 不应包含这些表。故意不使用 IF NOT EXISTS，避免把不完整的手工 schema
    // 误判成成功迁移。
    sqlx::query(
        r#"
        CREATE TABLE key_generation_requests (
            request_id TEXT COLLATE BINARY NOT NULL PRIMARY KEY,
            account_id TEXT COLLATE BINARY NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('initial', 'rotate')),
            status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
            expected_key_version INTEGER CHECK(expected_key_version IS NULL OR expected_key_version >= 1),
            reviewer_account_id TEXT COLLATE BINARY,
            requested_at INTEGER NOT NULL,
            reviewed_at INTEGER,
            approved_expires_at INTEGER,
            FOREIGN KEY(account_id) REFERENCES web_accounts(account_id) ON DELETE CASCADE,
            CHECK (
                (kind = 'initial' AND expected_key_version IS NULL) OR
                (kind = 'rotate' AND expected_key_version IS NOT NULL)
            ),
            CHECK (
                (status = 'pending' AND reviewer_account_id IS NULL
                    AND reviewed_at IS NULL AND approved_expires_at IS NULL) OR
                (status = 'approved' AND reviewer_account_id IS NOT NULL
                    AND reviewed_at IS NOT NULL AND approved_expires_at IS NOT NULL) OR
                (status = 'rejected' AND reviewer_account_id IS NOT NULL
                    AND reviewed_at IS NOT NULL AND approved_expires_at IS NULL)
            )
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX idx_key_requests_one_pending_per_account \
         ON key_generation_requests(account_id) WHERE status = 'pending'",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_key_requests_pending_order \
         ON key_generation_requests(status, requested_at, request_id)",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE user_access_records (
            record_id INTEGER NOT NULL PRIMARY KEY,
            username TEXT COLLATE BINARY NOT NULL,
            protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
            target_host TEXT NOT NULL CHECK(length(target_host) > 0 AND length(target_host) <= 1024),
            target_port INTEGER NOT NULL CHECK(target_port BETWEEN 1 AND 65535),
            accessed_at INTEGER NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
                ON UPDATE CASCADE ON DELETE CASCADE
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_access_records_user_time \
         ON user_access_records(username, accessed_at DESC, record_id DESC)",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query("CREATE INDEX idx_access_records_time ON user_access_records(accessed_at)")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "INSERT INTO app_metadata (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO NOTHING",
    )
    .bind(ACCESS_LOG_RETENTION_DAYS_KEY)
    .bind(DEFAULT_ACCESS_LOG_RETENTION_DAYS.to_string())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
