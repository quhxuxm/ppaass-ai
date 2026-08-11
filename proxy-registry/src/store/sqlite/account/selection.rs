use super::super::*;

impl SqliteUserRepository {
    pub(super) async fn select_proxy_addresses(
        &self,
        account_id: &str,
        proxy_address_ids: &[String],
        required_permission: &str,
    ) -> Result<ManagedUser> {
        let account_id = normalize_account_id(account_id)?;
        let proxy_address_ids = normalize_proxy_address_ids(proxy_address_ids)?;
        let permission = normalize_permissions(&[required_permission.to_string()])?
            .into_iter()
            .next()
            .expect("单个权限规范化后不会为空");
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let account = fetch_account_by_id(&mut transaction, &account_id)
            .await?
            .ok_or_else(|| UserRepositoryError::NotFound(account_id.clone()))?;
        if account.status != AccountStatus::Active {
            return Err(UserRepositoryError::ProxyEntrySelectionForbidden(
                account_id,
            ));
        }
        let profile = match account.linked_username.as_deref() {
            Some(username) => fetch_profile(&mut transaction, username).await?,
            None => None,
        };
        let allowed = account.role == AccountRole::Admin
            || profile.as_ref().is_some_and(|profile| {
                profile.enabled && profile.permissions.contains(&permission)
            });
        if !allowed {
            return Err(UserRepositoryError::ProxyEntrySelectionForbidden(
                account.account_id,
            ));
        }
        for proxy_address_id in &proxy_address_ids {
            let assigned: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM account_proxy_addresses \
                 WHERE account_id = ? AND proxy_address_id = ?)",
            )
            .bind(&account.account_id)
            .bind(proxy_address_id)
            .fetch_one(&mut *transaction)
            .await?;
            if !assigned {
                return Err(UserRepositoryError::ProxyEntryNotAssigned(
                    proxy_address_id.clone(),
                ));
            }
            let address = fetch_proxy_address(&mut transaction, proxy_address_id)
                .await?
                .ok_or_else(|| {
                    UserRepositoryError::ProxyAddressNotFound(proxy_address_id.clone())
                })?;
            if !address.enabled {
                return Err(UserRepositoryError::ProxyAddressDisabled(
                    proxy_address_id.clone(),
                ));
            }
        }
        let timestamp = now();
        sqlx::query("DELETE FROM account_proxy_entry_selections WHERE account_id = ?")
            .bind(&account.account_id)
            .execute(&mut *transaction)
            .await?;
        for proxy_address_id in &proxy_address_ids {
            sqlx::query(
                "INSERT INTO account_proxy_entry_selections \
                 (account_id, proxy_address_id, selected_at) VALUES (?, ?, ?)",
            )
            .bind(&account.account_id)
            .bind(proxy_address_id)
            .bind(timestamp)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query("UPDATE web_accounts SET updated_at = ? WHERE account_id = ?")
            .bind(timestamp)
            .bind(&account.account_id)
            .execute(&mut *transaction)
            .await?;
        insert_agent_event(
            &mut transaction,
            PROFILE_CHANGED_EVENT,
            Some(&account.account_id),
            timestamp,
        )
        .await?;
        let managed = fetch_managed_for_account(&mut transaction, account).await?;
        transaction.commit().await?;
        info!(
            account_id,
            count = proxy_address_ids.len(),
            "用户已选择 Proxy Entry"
        );
        Ok(managed)
    }
}
