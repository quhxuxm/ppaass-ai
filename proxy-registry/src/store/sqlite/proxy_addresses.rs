use super::*;

const PROXY_ADDRESS_SELECT: &str = "proxy_address_id, label, address, enabled, created_at, updated_at, \
     entry_id, entry_version, entry_first_registered_at, entry_last_heartbeat_at";

fn row_to_proxy_address(row: SqliteRow) -> Result<ProxyAddress> {
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
}

pub(super) async fn fetch_proxy_address(
    connection: &mut SqliteConnection,
    proxy_address_id: &str,
) -> Result<Option<ProxyAddress>> {
    let query =
        format!("SELECT {PROXY_ADDRESS_SELECT} FROM proxy_addresses WHERE proxy_address_id = ?");
    sqlx::query(&query)
        .bind(proxy_address_id)
        .fetch_optional(&mut *connection)
        .await?
        .map(row_to_proxy_address)
        .transpose()
}

pub(super) async fn fetch_assigned_proxy_addresses(
    connection: &mut SqliteConnection,
    account_id: &str,
) -> Result<Vec<ProxyAddress>> {
    let query = format!(
        "SELECT {} FROM proxy_addresses p \
         INNER JOIN account_proxy_addresses a \
             ON a.proxy_address_id = p.proxy_address_id \
         WHERE a.account_id = ? \
         ORDER BY p.address COLLATE BINARY, p.proxy_address_id COLLATE BINARY",
        PROXY_ADDRESS_SELECT
            .split(", ")
            .map(|column| format!("p.{column}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    sqlx::query(&query)
        .bind(account_id)
        .fetch_all(&mut *connection)
        .await?
        .into_iter()
        .map(row_to_proxy_address)
        .collect()
}

pub(super) async fn replace_account_proxy_addresses(
    transaction: &mut Transaction<'_, Sqlite>,
    account_id: &str,
    proxy_address_ids: &[String],
    timestamp: i64,
) -> Result<()> {
    let proxy_address_ids = normalize_proxy_address_ids(proxy_address_ids)?;
    for proxy_address_id in &proxy_address_ids {
        let address = fetch_proxy_address(&mut *transaction, proxy_address_id)
            .await?
            .ok_or_else(|| UserRepositoryError::ProxyAddressNotFound(proxy_address_id.clone()))?;
        if !address.enabled {
            return Err(UserRepositoryError::ProxyAddressDisabled(
                proxy_address_id.clone(),
            ));
        }
    }

    sqlx::query("DELETE FROM account_proxy_addresses WHERE account_id = ?")
        .bind(account_id)
        .execute(&mut **transaction)
        .await?;
    for proxy_address_id in proxy_address_ids {
        sqlx::query(
            "INSERT INTO account_proxy_addresses \
             (account_id, proxy_address_id, assigned_at) VALUES (?, ?, ?)",
        )
        .bind(account_id)
        .bind(proxy_address_id)
        .bind(timestamp)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

impl SqliteUserRepository {
    async fn list_proxy_addresses(&self) -> Result<Vec<ProxyAddress>> {
        let query = format!(
            "SELECT {PROXY_ADDRESS_SELECT} FROM proxy_addresses \
             ORDER BY label COLLATE BINARY, address COLLATE BINARY"
        );
        sqlx::query(&query)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(row_to_proxy_address)
            .collect()
    }

    async fn create_proxy_address(&self, input: NewProxyAddress) -> Result<ProxyAddress> {
        let proxy_address_id = normalize_proxy_address_id(&input.proxy_address_id)?;
        let address = normalize_proxy_address(&input.address)?;
        let label = if input.label.trim().is_empty() {
            address.clone()
        } else {
            normalize_proxy_address_label(&input.label)?
        };
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proxy_addresses")
            .fetch_one(&mut *transaction)
            .await?;
        if count >= MAX_PROXY_ADDRESS_CATALOG_SIZE {
            return Err(UserRepositoryError::ProxyAddressCapacity);
        }
        let conflict: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM proxy_addresses \
             WHERE proxy_address_id = ? OR address = ?)",
        )
        .bind(&proxy_address_id)
        .bind(&address)
        .fetch_one(&mut *transaction)
        .await?;
        if conflict {
            return Err(UserRepositoryError::ProxyAddressConflict(address));
        }
        let timestamp = now();
        sqlx::query(
            "INSERT INTO proxy_addresses \
             (proxy_address_id, label, address, enabled, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&proxy_address_id)
        .bind(&label)
        .bind(&address)
        .bind(input.enabled)
        .bind(timestamp)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
        let created = fetch_proxy_address(&mut transaction, &proxy_address_id)
            .await?
            .ok_or_else(|| UserRepositoryError::ProxyAddressNotFound(proxy_address_id.clone()))?;
        insert_agent_event(
            &mut transaction,
            ADMIN_KEY_REQUESTS_CHANGED_EVENT,
            None,
            timestamp,
        )
        .await?;
        transaction.commit().await?;
        info!(proxy_address_id, address, "Proxy 地址目录项已创建");
        Ok(created)
    }

    async fn update_proxy_address(
        &self,
        proxy_address_id: &str,
        update: ProxyAddressUpdate,
    ) -> Result<ProxyAddress> {
        let proxy_address_id = normalize_proxy_address_id(proxy_address_id)?;
        if update.is_empty() {
            return Err(ValidationError::EmptyUpdate.into());
        }
        let address = update
            .address
            .as_deref()
            .map(normalize_proxy_address)
            .transpose()?;
        let changed_by = update
            .changed_by
            .map(|actor| {
                Ok::<_, UserRepositoryError>(AccountActor {
                    account_id: normalize_account_id(&actor.account_id)?,
                    login_name: normalize_username(&actor.login_name)?,
                })
            })
            .transpose()?;
        let audit_reason = if update.enabled.is_some() {
            let actor = changed_by.as_ref().ok_or_else(|| {
                ValidationError::InvalidAccountField(
                    "修改服务器状态时必须提供操作管理员".to_string(),
                )
            })?;
            let reason =
                normalize_audit_reason(update.audit_reason.as_deref().unwrap_or_default())?;
            Some((actor.clone(), reason))
        } else {
            None
        };
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if let Some((actor, _)) = audit_reason.as_ref() {
            let administrator = fetch_account_by_id(&mut transaction, &actor.account_id)
                .await?
                .filter(|candidate| candidate.login_name == actor.login_name)
                .ok_or_else(|| UserRepositoryError::ReviewerNotActiveAdmin {
                    account_id: actor.account_id.clone(),
                })?;
            ensure_active_admin(&administrator)?;
        }
        let mut current = fetch_proxy_address(&mut transaction, &proxy_address_id)
            .await?
            .ok_or_else(|| UserRepositoryError::ProxyAddressNotFound(proxy_address_id.clone()))?;
        let previous_enabled = current.enabled;
        let label = update
            .label
            .as_deref()
            .map(|label| {
                if label.trim().is_empty() {
                    Ok(address
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(|| current.address.clone()))
                } else {
                    normalize_proxy_address_label(label)
                }
            })
            .transpose()?;
        if update.enabled == Some(false) && current.enabled {
            ensure_proxy_address_unassigned(&mut transaction, &proxy_address_id).await?;
        }
        if let Some(address) = address {
            let conflict: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM proxy_addresses \
                 WHERE address = ? AND proxy_address_id <> ?)",
            )
            .bind(&address)
            .bind(&proxy_address_id)
            .fetch_one(&mut *transaction)
            .await?;
            if conflict {
                return Err(UserRepositoryError::ProxyAddressConflict(address));
            }
            current.address = address;
        }
        if let Some(label) = label {
            current.label = label;
        }
        if let Some(enabled) = update.enabled {
            current.enabled = enabled;
        }
        current.updated_at = now();
        sqlx::query(
            "UPDATE proxy_addresses SET label = ?, address = ?, enabled = ?, updated_at = ? \
             WHERE proxy_address_id = ?",
        )
        .bind(&current.label)
        .bind(&current.address)
        .bind(current.enabled)
        .bind(current.updated_at)
        .bind(&proxy_address_id)
        .execute(&mut *transaction)
        .await?;
        if previous_enabled != current.enabled
            && let Some((actor, reason)) = audit_reason
        {
            insert_audit_event(
                &mut transaction,
                NewAuditEvent {
                    action: if current.enabled {
                        AuditAction::ProxyServerEnabled
                    } else {
                        AuditAction::ProxyServerDisabled
                    },
                    actor_account_id: actor.account_id,
                    actor_login_name: actor.login_name,
                    target_kind: AuditTargetKind::ProxyServer,
                    target_id: current.proxy_address_id.clone(),
                    target_name: current.label.clone(),
                    context_id: None,
                    reason: Some(reason),
                    previous_value: Some(previous_enabled.to_string()),
                    new_value: Some(current.enabled.to_string()),
                    created_at: current.updated_at,
                },
            )
            .await?;
        }
        insert_agent_event(
            &mut transaction,
            PROFILES_CHANGED_EVENT,
            None,
            current.updated_at,
        )
        .await?;
        insert_agent_event(
            &mut transaction,
            ADMIN_KEY_REQUESTS_CHANGED_EVENT,
            None,
            current.updated_at,
        )
        .await?;
        transaction.commit().await?;
        info!(proxy_address_id, "Proxy 地址目录项已更新");
        Ok(current)
    }

    async fn delete_proxy_address(&self, proxy_address_id: &str) -> Result<()> {
        let proxy_address_id = normalize_proxy_address_id(proxy_address_id)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let current = fetch_proxy_address(&mut transaction, &proxy_address_id)
            .await?
            .ok_or_else(|| UserRepositoryError::ProxyAddressNotFound(proxy_address_id.clone()))?;
        let timestamp = now();
        sqlx::query(
            "UPDATE web_accounts SET updated_at = ? WHERE account_id IN \
             (SELECT account_id FROM account_proxy_addresses WHERE proxy_address_id = ?)",
        )
        .bind(timestamp)
        .bind(&current.proxy_address_id)
        .execute(&mut *transaction)
        .await?;
        let unassigned_accounts =
            sqlx::query("DELETE FROM account_proxy_addresses WHERE proxy_address_id = ?")
                .bind(&current.proxy_address_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        sqlx::query("DELETE FROM proxy_addresses WHERE proxy_address_id = ?")
            .bind(&current.proxy_address_id)
            .execute(&mut *transaction)
            .await?;
        insert_agent_event(&mut transaction, PROFILES_CHANGED_EVENT, None, timestamp).await?;
        insert_agent_event(
            &mut transaction,
            ADMIN_KEY_REQUESTS_CHANGED_EVENT,
            None,
            timestamp,
        )
        .await?;
        transaction.commit().await?;
        info!(
            proxy_address_id = current.proxy_address_id,
            unassigned_accounts, "Proxy 地址目录项已删除"
        );
        Ok(())
    }
}

async fn ensure_proxy_address_unassigned(
    transaction: &mut Transaction<'_, Sqlite>,
    proxy_address_id: &str,
) -> Result<()> {
    let assigned: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM account_proxy_addresses WHERE proxy_address_id = ?)",
    )
    .bind(proxy_address_id)
    .fetch_one(&mut **transaction)
    .await?;
    if assigned {
        return Err(UserRepositoryError::ProxyAddressInUse(
            proxy_address_id.to_string(),
        ));
    }
    Ok(())
}

#[async_trait]
impl ProxyAddressRepository for SqliteUserRepository {
    async fn list_proxy_addresses(&self) -> Result<Vec<ProxyAddress>> {
        SqliteUserRepository::list_proxy_addresses(self).await
    }

    async fn create_proxy_address(&self, address: NewProxyAddress) -> Result<ProxyAddress> {
        SqliteUserRepository::create_proxy_address(self, address).await
    }

    async fn update_proxy_address(
        &self,
        proxy_address_id: &str,
        update: ProxyAddressUpdate,
    ) -> Result<ProxyAddress> {
        SqliteUserRepository::update_proxy_address(self, proxy_address_id, update).await
    }

    async fn delete_proxy_address(&self, proxy_address_id: &str) -> Result<()> {
        SqliteUserRepository::delete_proxy_address(self, proxy_address_id).await
    }
}
