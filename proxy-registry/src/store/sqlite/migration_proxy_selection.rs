use super::*;

pub(super) async fn create_v14_proxy_entry_selections(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS account_proxy_entry_selections (
            account_id TEXT COLLATE BINARY NOT NULL PRIMARY KEY,
            proxy_address_id TEXT COLLATE BINARY NOT NULL,
            selected_at INTEGER NOT NULL,
            FOREIGN KEY(account_id) REFERENCES web_accounts(account_id) ON DELETE CASCADE,
            FOREIGN KEY(proxy_address_id) REFERENCES proxy_addresses(proxy_address_id)
                ON DELETE CASCADE
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_account_proxy_entry_selections_address \
         ON account_proxy_entry_selections(proxy_address_id, account_id)",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
