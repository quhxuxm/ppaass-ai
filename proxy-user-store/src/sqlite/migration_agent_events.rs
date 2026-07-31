use super::*;

pub(super) async fn create_v12_agent_event_log(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE registry_agent_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL CHECK(kind IN (
                'profile_changed',
                'profiles_changed',
                'key_request_changed',
                'admin_key_requests_changed'
            )),
            account_id TEXT,
            created_at INTEGER NOT NULL
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_registry_agent_events_created_at \
         ON registry_agent_events(created_at, event_id)",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE agent_web_session_handoffs (
            code_hash TEXT PRIMARY KEY,
            account_id TEXT NOT NULL
                REFERENCES web_accounts(account_id) ON DELETE CASCADE,
            account_auth_version INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_agent_web_session_handoffs_account \
         ON agent_web_session_handoffs(account_id, expires_at)",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
