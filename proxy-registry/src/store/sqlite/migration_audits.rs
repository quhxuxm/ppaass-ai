use super::*;

pub(super) async fn create_v11_operation_audits(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE operation_audits (
            audit_id INTEGER NOT NULL PRIMARY KEY,
            action TEXT COLLATE BINARY NOT NULL,
            actor_account_id TEXT COLLATE BINARY NOT NULL,
            actor_login_name TEXT COLLATE BINARY NOT NULL,
            target_kind TEXT COLLATE BINARY NOT NULL,
            target_id TEXT COLLATE BINARY NOT NULL,
            target_name TEXT COLLATE BINARY NOT NULL,
            context_id TEXT COLLATE BINARY,
            reason TEXT,
            previous_value TEXT,
            new_value TEXT,
            created_at INTEGER NOT NULL,
            CHECK(action IN (
                'key_request_approved', 'key_request_rejected', 'key_regenerated',
                'proxy_access_enabled', 'proxy_access_disabled',
                'web_login_enabled', 'web_login_disabled',
                'proxy_server_enabled', 'proxy_server_disabled',
                'permissions_updated'
            )),
            CHECK(target_kind IN ('user', 'proxy_server')),
            CHECK(length(actor_account_id) BETWEEN 1 AND 128),
            CHECK(length(actor_login_name) BETWEEN 1 AND 128),
            CHECK(length(target_id) BETWEEN 1 AND 128),
            CHECK(length(target_name) BETWEEN 1 AND 256),
            CHECK(context_id IS NULL OR length(context_id) BETWEEN 1 AND 128),
            CHECK(reason IS NULL OR length(reason) BETWEEN 1 AND 2000),
            CHECK(previous_value IS NULL OR length(previous_value) <= 8192),
            CHECK(new_value IS NULL OR length(new_value) <= 8192)
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_operation_audits_time \
         ON operation_audits(created_at DESC, audit_id DESC)",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
