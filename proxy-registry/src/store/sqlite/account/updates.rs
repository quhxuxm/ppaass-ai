use super::super::*;

impl SqliteUserRepository {
    #[instrument(skip(self, update), fields(account_id))]
    pub(super) async fn update_managed_user(
        &self,
        account_id: &str,
        update: ManagedUserUpdate,
    ) -> Result<ManagedUser> {
        let account_id = normalize_account_id(account_id)?;
        if update.is_empty() {
            return Err(ValidationError::EmptyUpdate.into());
        }
        let permissions = update
            .permissions
            .as_deref()
            .map(normalize_permissions)
            .transpose()?;
        let proxy_address_ids = update
            .proxy_address_ids
            .as_deref()
            .map(normalize_proxy_address_ids)
            .transpose()?;
        let display_name = update
            .display_name
            .map(|value| {
                value
                    .map(|value| normalize_field("display_name", &value, MAX_DISPLAY_NAME_BYTES))
                    .transpose()
            })
            .transpose()?;
        let email = update
            .email
            .map(|value| {
                value
                    .map(|value| normalize_field("email", &value, MAX_EMAIL_BYTES))
                    .transpose()
            })
            .transpose()?;
        let avatar_url = update
            .avatar_url
            .map(|value| {
                value
                    .map(|value| normalize_field("avatar_url", &value, MAX_AVATAR_URL_BYTES))
                    .transpose()
            })
            .transpose()?;
        let disabled_by = update
            .disabled_by
            .map(|actor| {
                Ok::<_, UserRepositoryError>(AccountActor {
                    account_id: normalize_account_id(&actor.account_id)?,
                    login_name: normalize_username(&actor.login_name)?,
                })
            })
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
        if disabled_by.is_some() && update.status != Some(AccountStatus::Disabled) {
            return Err(ValidationError::InvalidAccountField(
                "disabled_by 只能用于停用账号".to_string(),
            )
            .into());
        }

        let profile_update_requested =
            update.enabled.is_some() || permissions.is_some() || update.expires_at.is_some();
        let audit_requested =
            update.status.is_some() || update.enabled.is_some() || permissions.is_some();
        let audit_actor = changed_by.or_else(|| disabled_by.clone());
        if audit_requested && audit_actor.is_none() {
            return Err(ValidationError::InvalidAccountField(
                "修改登录状态、代理连接状态或权限时必须提供操作管理员".to_string(),
            )
            .into());
        }
        let audit_reason = if audit_requested {
            Some(normalize_audit_reason(
                update.audit_reason.as_deref().unwrap_or_default(),
            )?)
        } else {
            None
        };
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let Some(mut account) = fetch_account_by_id(&mut transaction, &account_id).await? else {
            return Err(UserRepositoryError::NotFound(account_id));
        };
        let target_role = update.role.unwrap_or(account.role);
        let target_status = update.status.unwrap_or(account.status);
        guard_root_admin(&account, Some(target_role), Some(target_status))?;
        let newly_disabled =
            account.status != AccountStatus::Disabled && target_status == AccountStatus::Disabled;
        if let Some(actor) = audit_actor.as_ref() {
            let administrator = fetch_account_by_id(&mut transaction, &actor.account_id)
                .await?
                .filter(|candidate| candidate.login_name == actor.login_name)
                .ok_or_else(|| UserRepositoryError::ReviewerNotActiveAdmin {
                    account_id: actor.account_id.clone(),
                })?;
            ensure_active_admin(&administrator)?;
        }
        if newly_disabled && let Some(actor) = disabled_by.as_ref() {
            let reviewer = fetch_account_by_id(&mut transaction, &actor.account_id)
                .await?
                .filter(|candidate| {
                    candidate.login_name == actor.login_name
                        && candidate.role == AccountRole::Admin
                        && candidate.status == AccountStatus::Active
                })
                .ok_or_else(|| UserRepositoryError::ReviewerNotActiveAdmin {
                    account_id: actor.account_id.clone(),
                })?;
            debug_assert_eq!(reviewer.login_name, actor.login_name);
        }

        let mut profile = match account.linked_username.as_deref() {
            Some(username) => fetch_profile(&mut transaction, username).await?,
            None => None,
        };
        let previous_status = account.status;
        let previous_enabled = profile.as_ref().map(|profile| profile.enabled);
        let previous_permissions = profile.as_ref().map(|profile| profile.permissions.clone());
        if profile_update_requested && profile.is_none() {
            return Err(UserRepositoryError::NotFound(format!(
                "账号 {} 未关联 Proxy 用户",
                account.account_id
            )));
        }

        let auth_changed = account.role != target_role || account.status != target_status;
        account.role = target_role;
        account.status = target_status;
        if let Some(display_name) = display_name {
            account.display_name = display_name;
        }
        if let Some(email) = email {
            account.email = email;
        }
        if let Some(avatar_url) = avatar_url {
            account.avatar_url = avatar_url;
        }
        if auth_changed {
            account.auth_version = account.auth_version.checked_add(1).ok_or_else(|| {
                UserRepositoryError::InvalidSchema(format!(
                    "账号 {} 的 auth_version 已溢出",
                    account.account_id
                ))
            })?;
        }
        account.updated_at = now();
        sqlx::query(
            "UPDATE web_accounts SET role = ?, status = ?, display_name = ?, email = ?, \
             avatar_url = ?, auth_version = ?, updated_at = ? WHERE account_id = ?",
        )
        .bind(account.role.as_str())
        .bind(account.status.as_str())
        .bind(&account.display_name)
        .bind(&account.email)
        .bind(&account.avatar_url)
        .bind(account.auth_version)
        .bind(account.updated_at)
        .bind(&account.account_id)
        .execute(&mut *transaction)
        .await?;
        if newly_disabled && let Some(actor) = disabled_by {
            sqlx::query(
                "INSERT INTO account_disable_audits \
                 (target_account_id, target_login_name, admin_account_id, \
                  admin_login_name, disabled_at) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&account.account_id)
            .bind(&account.login_name)
            .bind(actor.account_id)
            .bind(actor.login_name)
            .bind(account.updated_at)
            .execute(&mut *transaction)
            .await?;
        }

        if let Some(profile) = profile.as_mut() {
            if let Some(enabled) = update.enabled {
                profile.enabled = enabled;
            }
            if let Some(permissions) = permissions {
                profile.permissions = permissions;
            }
            if let Some(expires_at) = update.expires_at {
                profile.expires_at = expires_at;
            }
            if profile_update_requested {
                profile.updated_at = now();
                sqlx::query(
                    "UPDATE users SET permissions = ?, enabled = ?, expires_at = ?, \
                     updated_at = ? WHERE username = ?",
                )
                .bind(encode_permissions(&profile.permissions))
                .bind(profile.enabled)
                .bind(profile.expires_at)
                .bind(profile.updated_at)
                .bind(&profile.username)
                .execute(&mut *transaction)
                .await?;
            }
        }
        if let Some(proxy_address_ids) = proxy_address_ids {
            replace_account_proxy_addresses(
                &mut transaction,
                &account.account_id,
                &proxy_address_ids,
                now(),
            )
            .await?;
        }
        if let Some(actor) = audit_actor {
            let target_id = account.account_id.clone();
            let target_name = account.login_name.clone();
            if previous_status != account.status {
                insert_audit_event(
                    &mut transaction,
                    NewAuditEvent {
                        action: if account.status == AccountStatus::Active {
                            AuditAction::WebLoginEnabled
                        } else {
                            AuditAction::WebLoginDisabled
                        },
                        actor_account_id: actor.account_id.clone(),
                        actor_login_name: actor.login_name.clone(),
                        target_kind: AuditTargetKind::User,
                        target_id: target_id.clone(),
                        target_name: target_name.clone(),
                        context_id: None,
                        reason: audit_reason.clone(),
                        previous_value: Some(previous_status.as_str().to_string()),
                        new_value: Some(account.status.as_str().to_string()),
                        created_at: account.updated_at,
                    },
                )
                .await?;
            }
            if let (Some(previous), Some(profile)) = (previous_enabled, profile.as_ref())
                && previous != profile.enabled
            {
                insert_audit_event(
                    &mut transaction,
                    NewAuditEvent {
                        action: if profile.enabled {
                            AuditAction::ProxyAccessEnabled
                        } else {
                            AuditAction::ProxyAccessDisabled
                        },
                        actor_account_id: actor.account_id.clone(),
                        actor_login_name: actor.login_name.clone(),
                        target_kind: AuditTargetKind::User,
                        target_id: target_id.clone(),
                        target_name: target_name.clone(),
                        context_id: None,
                        reason: audit_reason.clone(),
                        previous_value: Some(previous.to_string()),
                        new_value: Some(profile.enabled.to_string()),
                        created_at: profile.updated_at,
                    },
                )
                .await?;
            }
            if let (Some(previous), Some(profile)) = (previous_permissions, profile.as_ref())
                && previous != profile.permissions
            {
                insert_audit_event(
                    &mut transaction,
                    NewAuditEvent {
                        action: AuditAction::PermissionsUpdated,
                        actor_account_id: actor.account_id,
                        actor_login_name: actor.login_name,
                        target_kind: AuditTargetKind::User,
                        target_id,
                        target_name,
                        context_id: None,
                        reason: audit_reason,
                        previous_value: Some(serde_json::to_string(&previous).map_err(
                            |error| UserRepositoryError::InvalidSchema(error.to_string()),
                        )?),
                        new_value: Some(serde_json::to_string(&profile.permissions).map_err(
                            |error| UserRepositoryError::InvalidSchema(error.to_string()),
                        )?),
                        created_at: profile.updated_at,
                    },
                )
                .await?;
            }
        }

        insert_agent_event(
            &mut transaction,
            PROFILE_CHANGED_EVENT,
            Some(&account.account_id),
            account.updated_at,
        )
        .await?;
        insert_agent_event(
            &mut transaction,
            ADMIN_KEY_REQUESTS_CHANGED_EVENT,
            None,
            account.updated_at,
        )
        .await?;
        let managed = fetch_managed_for_account(&mut transaction, account).await?;
        transaction.commit().await?;
        info!(account_id, "托管用户配置已更新");
        Ok(managed)
    }
}
