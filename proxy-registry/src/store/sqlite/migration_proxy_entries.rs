use super::*;

pub(super) async fn create_v13_proxy_entry_columns(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<()> {
    for statement in [
        "ALTER TABLE proxy_addresses ADD COLUMN entry_id TEXT COLLATE BINARY",
        "ALTER TABLE proxy_addresses ADD COLUMN entry_version TEXT",
        "ALTER TABLE proxy_addresses ADD COLUMN entry_first_registered_at INTEGER",
        "ALTER TABLE proxy_addresses ADD COLUMN entry_last_heartbeat_at INTEGER",
        "CREATE UNIQUE INDEX idx_proxy_addresses_entry_id ON proxy_addresses(entry_id)",
        "CREATE INDEX idx_proxy_addresses_entry_heartbeat \
         ON proxy_addresses(entry_last_heartbeat_at, entry_id)",
    ] {
        sqlx::query(statement).execute(&mut **transaction).await?;
    }
    Ok(())
}
