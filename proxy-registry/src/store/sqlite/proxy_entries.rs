use super::*;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

fn generated_proxy_address_id(entry_id: &str) -> String {
    let mut value = String::from("pxy_entry_");
    for byte in Sha256::digest(entry_id.as_bytes()) {
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

#[async_trait]
impl ProxyEntryRepository for SqliteUserRepository {
    async fn register_proxy_entry(&self, registration: ProxyEntryRegistration) -> Result<()> {
        let address = normalize_proxy_address(&registration.advertised_address)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let existing_by_entry: Option<(String, String)> = sqlx::query_as(
            "SELECT proxy_address_id, address FROM proxy_addresses WHERE entry_id = ?",
        )
        .bind(&registration.entry_id)
        .fetch_optional(&mut *transaction)
        .await?;

        if let Some((proxy_address_id, current_address)) = existing_by_entry {
            if current_address != address {
                let conflict: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM proxy_addresses \
                     WHERE address = ? AND proxy_address_id <> ?)",
                )
                .bind(&address)
                .bind(&proxy_address_id)
                .fetch_one(&mut *transaction)
                .await?;
                if conflict {
                    return Err(UserRepositoryError::ProxyEntryAddressConflict(address));
                }
                sqlx::query(
                    "UPDATE proxy_addresses SET address = ?, entry_version = ?, \
                     entry_last_heartbeat_at = ?, updated_at = ? WHERE proxy_address_id = ?",
                )
                .bind(&address)
                .bind(&registration.version)
                .bind(registration.received_at)
                .bind(registration.received_at)
                .bind(&proxy_address_id)
                .execute(&mut *transaction)
                .await?;
                insert_agent_event(
                    &mut transaction,
                    PROFILES_CHANGED_EVENT,
                    None,
                    registration.received_at,
                )
                .await?;
            } else {
                sqlx::query(
                    "UPDATE proxy_addresses SET entry_version = ?, entry_last_heartbeat_at = ? \
                     WHERE proxy_address_id = ?",
                )
                .bind(&registration.version)
                .bind(registration.received_at)
                .bind(&proxy_address_id)
                .execute(&mut *transaction)
                .await?;
            }
            transaction.commit().await?;
            return Ok(());
        }

        let existing_by_address: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT proxy_address_id, entry_id FROM proxy_addresses WHERE address = ?",
        )
        .bind(&address)
        .fetch_optional(&mut *transaction)
        .await?;
        match existing_by_address {
            Some((_, Some(_))) => {
                return Err(UserRepositoryError::ProxyEntryAddressConflict(address));
            }
            Some((proxy_address_id, None)) => {
                sqlx::query(
                    "UPDATE proxy_addresses SET entry_id = ?, entry_version = ?, \
                     entry_first_registered_at = ?, entry_last_heartbeat_at = ?, updated_at = ? \
                     WHERE proxy_address_id = ?",
                )
                .bind(&registration.entry_id)
                .bind(&registration.version)
                .bind(registration.received_at)
                .bind(registration.received_at)
                .bind(registration.received_at)
                .bind(proxy_address_id)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
                return Ok(());
            }
            None => {}
        }

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proxy_addresses")
            .fetch_one(&mut *transaction)
            .await?;
        if count >= MAX_PROXY_ADDRESS_CATALOG_SIZE {
            return Err(UserRepositoryError::ProxyAddressCapacity);
        }
        sqlx::query(
            "INSERT INTO proxy_addresses \
             (proxy_address_id, label, address, enabled, created_at, updated_at, entry_id, \
              entry_version, entry_first_registered_at, entry_last_heartbeat_at) \
             VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)",
        )
        .bind(generated_proxy_address_id(&registration.entry_id))
        .bind(&registration.entry_id)
        .bind(&address)
        .bind(registration.received_at)
        .bind(registration.received_at)
        .bind(&registration.entry_id)
        .bind(&registration.version)
        .bind(registration.received_at)
        .bind(registration.received_at)
        .execute(&mut *transaction)
        .await?;
        insert_agent_event(
            &mut transaction,
            ADMIN_KEY_REQUESTS_CHANGED_EVENT,
            None,
            registration.received_at,
        )
        .await?;
        transaction.commit().await?;
        info!(
            entry_id = registration.entry_id,
            address, "Proxy Entry 已注册到地址目录"
        );
        Ok(())
    }
}
