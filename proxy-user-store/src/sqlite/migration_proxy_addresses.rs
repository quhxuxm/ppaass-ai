use super::*;

pub(super) async fn create_v8_proxy_address_tables(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE proxy_addresses (
            proxy_address_id TEXT COLLATE BINARY NOT NULL PRIMARY KEY,
            label TEXT NOT NULL CHECK(length(label) > 0 AND length(label) <= 128),
            address TEXT COLLATE BINARY NOT NULL UNIQUE
                CHECK(length(address) > 0 AND length(address) <= 512),
            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE account_proxy_addresses (
            account_id TEXT COLLATE BINARY NOT NULL,
            proxy_address_id TEXT COLLATE BINARY NOT NULL,
            assigned_at INTEGER NOT NULL,
            PRIMARY KEY(account_id, proxy_address_id),
            FOREIGN KEY(account_id) REFERENCES web_accounts(account_id) ON DELETE CASCADE,
            FOREIGN KEY(proxy_address_id) REFERENCES proxy_addresses(proxy_address_id)
                ON DELETE RESTRICT
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_account_proxy_addresses_address \
         ON account_proxy_addresses(proxy_address_id, account_id)",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
