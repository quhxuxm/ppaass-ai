use super::*;

pub(super) async fn fetch_selected_proxy_address(
    connection: &mut SqliteConnection,
    account_id: &str,
) -> Result<Option<ProxyAddress>> {
    let row = sqlx::query(
        "SELECT p.proxy_address_id, p.label, p.address, p.enabled, p.created_at, \
         p.updated_at, p.entry_id, p.entry_version, p.entry_first_registered_at, \
         p.entry_last_heartbeat_at FROM proxy_addresses p \
         INNER JOIN account_proxy_entry_selections s \
             ON s.proxy_address_id = p.proxy_address_id WHERE s.account_id = ?",
    )
    .bind(account_id)
    .fetch_optional(&mut *connection)
    .await?;
    row.map(|row| {
        Ok(ProxyAddress {
            proxy_address_id: row.try_get("proxy_address_id")?,
            label: row.try_get("label")?,
            address: row.try_get("address")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            entry_id: row.try_get("entry_id")?,
            entry_version: row.try_get("entry_version")?,
            entry_first_registered_at: row.try_get("entry_first_registered_at")?,
            entry_last_heartbeat_at: row.try_get("entry_last_heartbeat_at")?,
        })
    })
    .transpose()
}
