use super::super::*;

impl SqliteUserRepository {
    pub(super) async fn select_proxy_address(
        &self,
        account_id: &str,
        proxy_address_id: &str,
        required_permission: &str,
    ) -> Result<ManagedUser> {
        let account_id = normalize_account_id(account_id)?;
        let proxy_address_id = normalize_proxy_address_id(proxy_address_id)?;
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
        let address = fetch_proxy_address(&mut transaction, &proxy_address_id)
            .await?
            .ok_or_else(|| UserRepositoryError::ProxyAddressNotFound(proxy_address_id.clone()))?;
        if !address.enabled {
            return Err(UserRepositoryError::ProxyAddressDisabled(proxy_address_id));
        }
        let timestamp = now();
        sqlx::query(
            "INSERT INTO account_proxy_entry_selections \
             (account_id, proxy_address_id, selected_at) VALUES (?, ?, ?) \
             ON CONFLICT(account_id) DO UPDATE SET \
             proxy_address_id = excluded.proxy_address_id, selected_at = excluded.selected_at",
        )
        .bind(&account.account_id)
        .bind(&address.proxy_address_id)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await?;
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
        info!(account_id, proxy_address_id, "用户已选择 Proxy Entry");
        Ok(managed)
    }
}
