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

pub(super) async fn migrate_v15_proxy_entry_selections(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE account_proxy_entry_selections_v15 (
            account_id TEXT COLLATE BINARY NOT NULL,
            proxy_address_id TEXT COLLATE BINARY NOT NULL,
            selected_at INTEGER NOT NULL,
            PRIMARY KEY(account_id, proxy_address_id),
            FOREIGN KEY(account_id) REFERENCES web_accounts(account_id) ON DELETE CASCADE,
            FOREIGN KEY(proxy_address_id) REFERENCES proxy_addresses(proxy_address_id)
                ON DELETE CASCADE
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO account_proxy_entry_selections_v15 \
         (account_id, proxy_address_id, selected_at) \
         SELECT s.account_id, s.proxy_address_id, s.selected_at \
         FROM account_proxy_entry_selections s \
         INNER JOIN account_proxy_addresses a \
           ON a.account_id = s.account_id \
          AND a.proxy_address_id = s.proxy_address_id",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query("DROP TABLE account_proxy_entry_selections")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "ALTER TABLE account_proxy_entry_selections_v15 \
         RENAME TO account_proxy_entry_selections",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_account_proxy_entry_selections_address \
         ON account_proxy_entry_selections(proxy_address_id, account_id)",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
