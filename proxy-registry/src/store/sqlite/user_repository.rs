use super::*;

const MAX_AUTHORIZATION_SNAPSHOT_PAGE_SIZE: u16 = 256;

impl SqliteUserRepository {
    /// 使用完整的新用户模型创建 Proxy profile。
    pub async fn create_user_record(&self, user: NewUser) -> Result<UserRecord> {
        let user = normalize_new_user(user)?;
        let now = now();
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "INSERT INTO users \
             (username, public_key_pem, permissions, enabled, origin, key_version, \
              expires_at, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?) \
             ON CONFLICT(username) DO NOTHING",
        )
        .bind(&user.username)
        .bind(&user.public_key_pem)
        .bind(encode_permissions(&user.permissions))
        .bind(user.enabled)
        .bind(user.origin.as_str())
        .bind(user.expires_at)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::Conflict(user.username));
        }
        insert_agent_event(&mut transaction, PROFILES_CHANGED_EVENT, None, now).await?;
        transaction.commit().await?;
        info!(username = user.username, "Proxy 用户已创建");
        Ok(UserRecord {
            username: user.username,
            public_key_pem: user.public_key_pem,
            permissions: user.permissions,
            enabled: user.enabled,
            origin: user.origin,
            key_version: 1,
            expires_at: user.expires_at,
            created_at: now,
            updated_at: now,
        })
    }

    #[instrument(skip(self), fields(username))]
    async fn get_user(&self, username: &str) -> Result<Option<UserRecord>> {
        let username = normalize_username(username)?;
        let query = format!("SELECT {USER_SELECT} FROM users WHERE username = ?");
        let row = sqlx::query(&query)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_user).transpose()
    }

    #[instrument(skip(self))]
    async fn list_users(&self) -> Result<Vec<UserRecord>> {
        let query = format!("SELECT {USER_SELECT} FROM users ORDER BY username COLLATE BINARY");
        sqlx::query(&query)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(row_to_user)
            .collect()
    }

    #[instrument(skip(self))]
    async fn read_authorization_snapshot_page(
        &self,
        query: UserAuthorizationSnapshotQuery,
    ) -> Result<UserAuthorizationSnapshotPage> {
        if query.limit == 0 || query.limit > MAX_AUTHORIZATION_SNAPSHOT_PAGE_SIZE {
            return Err(UserRepositoryError::InvalidAuthorizationSnapshotLimit(
                query.limit,
            ));
        }
        let mut transaction = self.pool.begin().await?;
        let revision: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(event_id), 0) FROM registry_agent_events")
                .fetch_one(&mut *transaction)
                .await?;
        let revision = u64::try_from(revision).map_err(|_| {
            UserRepositoryError::InvalidSchema(
                "registry_agent_events.event_id 不能表示为非负修订号".to_string(),
            )
        })?;
        if let Some(expected) = query.expected_revision
            && expected != revision
        {
            transaction.rollback().await?;
            return Err(UserRepositoryError::AuthorizationSnapshotRevisionConflict {
                expected,
                actual: revision,
            });
        }

        let fetch_limit = i64::from(query.limit) + 1;
        let sql = if query.after_username.is_some() {
            format!(
                "SELECT {USER_SELECT} FROM users WHERE username > ? \
                 ORDER BY username LIMIT ?"
            )
        } else {
            format!("SELECT {USER_SELECT} FROM users ORDER BY username LIMIT ?")
        };
        let rows = if let Some(after_username) = query.after_username {
            sqlx::query(&sql)
                .bind(after_username)
                .bind(fetch_limit)
                .fetch_all(&mut *transaction)
                .await?
        } else {
            sqlx::query(&sql)
                .bind(fetch_limit)
                .fetch_all(&mut *transaction)
                .await?
        };
        let mut users = rows
            .into_iter()
            .map(row_to_user)
            .collect::<Result<Vec<_>>>()?;
        transaction.commit().await?;
        let has_more = users.len() > usize::from(query.limit);
        users.truncate(usize::from(query.limit));
        let next_cursor = has_more.then(|| {
            users
                .last()
                .expect("非零分页大小有下一页时当前页不能为空")
                .username
                .clone()
        });
        Ok(UserAuthorizationSnapshotPage {
            revision,
            users,
            next_cursor,
        })
    }

    #[instrument(skip(self, public_key_pem), fields(username))]
    async fn create_user(
        &self,
        username: &str,
        public_key_pem: &str,
        expires_at: Option<i64>,
    ) -> Result<UserRecord> {
        let mut user = NewUser::new(username, public_key_pem, UserOrigin::Admin);
        user.expires_at = expires_at;
        self.create_user_record(user).await
    }

    #[instrument(skip(self, update), fields(username))]
    async fn update_user(&self, username: &str, update: UserUpdate) -> Result<UserRecord> {
        let username = normalize_username(username)?;
        if update.is_empty() {
            return Err(ValidationError::EmptyUpdate.into());
        }
        let public_key_pem = update
            .public_key_pem
            .as_deref()
            .map(normalize_public_key_pem)
            .transpose()?;
        let permissions = update
            .permissions
            .as_deref()
            .map(normalize_permissions)
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
        if (update.enabled.is_some() || permissions.is_some()) && changed_by.is_none() {
            return Err(ValidationError::InvalidAccountField(
                "修改代理连接状态或权限时必须提供操作管理员".to_string(),
            )
            .into());
        }
        let audit_reason = if update.enabled.is_some() || permissions.is_some() {
            Some(normalize_audit_reason(
                update.audit_reason.as_deref().unwrap_or_default(),
            )?)
        } else {
            None
        };

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if let Some(actor) = changed_by.as_ref() {
            let administrator = fetch_account_by_id(&mut transaction, &actor.account_id)
                .await?
                .filter(|candidate| candidate.login_name == actor.login_name)
                .ok_or_else(|| UserRepositoryError::ReviewerNotActiveAdmin {
                    account_id: actor.account_id.clone(),
                })?;
            ensure_active_admin(&administrator)?;
        }
        let query = format!("SELECT {USER_SELECT} FROM users WHERE username = ?");
        let mut user = sqlx::query(&query)
            .bind(&username)
            .fetch_optional(&mut *transaction)
            .await?
            .map(row_to_user)
            .transpose()?
            .ok_or_else(|| UserRepositoryError::NotFound(username.clone()))?;
        let previous_enabled = user.enabled;
        let previous_permissions = user.permissions.clone();

        let key_changed = public_key_pem
            .as_ref()
            .is_some_and(|key| key != &user.public_key_pem);
        if let Some(public_key_pem) = public_key_pem {
            user.public_key_pem = public_key_pem;
        }
        if let Some(permissions) = permissions {
            user.permissions = permissions;
        }
        if let Some(enabled) = update.enabled {
            user.enabled = enabled;
        }
        if let Some(expires_at) = update.expires_at {
            user.expires_at = expires_at;
        }
        if key_changed {
            user.key_version = user.key_version.checked_add(1).ok_or_else(|| {
                UserRepositoryError::InvalidSchema(format!(
                    "用户 {} 的 key_version 已溢出",
                    user.username
                ))
            })?;
        }
        user.updated_at = now();

        sqlx::query(
            "UPDATE users SET public_key_pem = ?, permissions = ?, enabled = ?, \
             key_version = ?, expires_at = ?, updated_at = ? WHERE username = ?",
        )
        .bind(&user.public_key_pem)
        .bind(encode_permissions(&user.permissions))
        .bind(user.enabled)
        .bind(user.key_version)
        .bind(user.expires_at)
        .bind(user.updated_at)
        .bind(&user.username)
        .execute(&mut *transaction)
        .await?;

        if key_changed {
            // 独立更新公钥后，原托管私钥不再可信；只有 rotate_keypair 能原子保留二者。
            sqlx::query("DELETE FROM user_private_keys WHERE username = ?")
                .bind(&user.username)
                .execute(&mut *transaction)
                .await?;
        }
        if let Some(actor) = changed_by {
            if previous_enabled != user.enabled {
                insert_audit_event(
                    &mut transaction,
                    NewAuditEvent {
                        action: if user.enabled {
                            AuditAction::ProxyAccessEnabled
                        } else {
                            AuditAction::ProxyAccessDisabled
                        },
                        actor_account_id: actor.account_id.clone(),
                        actor_login_name: actor.login_name.clone(),
                        target_kind: AuditTargetKind::User,
                        target_id: user.username.clone(),
                        target_name: user.username.clone(),
                        context_id: None,
                        reason: audit_reason.clone(),
                        previous_value: Some(previous_enabled.to_string()),
                        new_value: Some(user.enabled.to_string()),
                        created_at: user.updated_at,
                    },
                )
                .await?;
            }
            if previous_permissions != user.permissions {
                insert_audit_event(
                    &mut transaction,
                    NewAuditEvent {
                        action: AuditAction::PermissionsUpdated,
                        actor_account_id: actor.account_id,
                        actor_login_name: actor.login_name,
                        target_kind: AuditTargetKind::User,
                        target_id: user.username.clone(),
                        target_name: user.username.clone(),
                        context_id: None,
                        reason: audit_reason,
                        previous_value: Some(
                            serde_json::to_string(&previous_permissions).map_err(|error| {
                                UserRepositoryError::InvalidSchema(error.to_string())
                            })?,
                        ),
                        new_value: Some(serde_json::to_string(&user.permissions).map_err(
                            |error| UserRepositoryError::InvalidSchema(error.to_string()),
                        )?),
                        created_at: user.updated_at,
                    },
                )
                .await?;
            }
        }
        insert_agent_event(
            &mut transaction,
            PROFILES_CHANGED_EVENT,
            None,
            user.updated_at,
        )
        .await?;
        transaction.commit().await?;
        info!(
            username = user.username,
            key_changed, "Proxy 用户配置已更新"
        );
        Ok(user)
    }

    #[instrument(skip(self), fields(username))]
    async fn delete_user(&self, username: &str) -> Result<()> {
        let username = normalize_username(username)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let account_query =
            format!("SELECT {ACCOUNT_SELECT} FROM web_accounts WHERE linked_username = ?");
        let linked_account = sqlx::query(&account_query)
            .bind(&username)
            .fetch_optional(&mut *transaction)
            .await?
            .map(row_to_account)
            .transpose()?;

        if let Some(account) = &linked_account {
            guard_root_admin(account, None, None)?;
            if account.status != AccountStatus::Disabled {
                return Err(UserRepositoryError::AccountMustBeDisabled(
                    account.account_id.clone(),
                ));
            }
            sqlx::query("DELETE FROM web_accounts WHERE account_id = ?")
                .bind(&account.account_id)
                .execute(&mut *transaction)
                .await?;
        }
        let result = sqlx::query("DELETE FROM users WHERE username = ?")
            .bind(&username)
            .execute(&mut *transaction)
            .await?;
        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(username));
        }
        insert_agent_event(&mut transaction, PROFILES_CHANGED_EVENT, None, now()).await?;
        transaction.commit().await?;
        info!(username, "Proxy 用户已删除");
        Ok(())
    }
}

#[async_trait]
impl UserRepository for SqliteUserRepository {
    async fn get_user(&self, username: &str) -> Result<Option<UserRecord>> {
        SqliteUserRepository::get_user(self, username).await
    }

    async fn list_users(&self) -> Result<Vec<UserRecord>> {
        SqliteUserRepository::list_users(self).await
    }

    async fn read_authorization_snapshot_page(
        &self,
        query: UserAuthorizationSnapshotQuery,
    ) -> Result<UserAuthorizationSnapshotPage> {
        SqliteUserRepository::read_authorization_snapshot_page(self, query).await
    }

    async fn create_user(
        &self,
        username: &str,
        public_key_pem: &str,
        expires_at: Option<i64>,
    ) -> Result<UserRecord> {
        SqliteUserRepository::create_user(self, username, public_key_pem, expires_at).await
    }

    async fn update_user(&self, username: &str, update: UserUpdate) -> Result<UserRecord> {
        SqliteUserRepository::update_user(self, username, update).await
    }

    async fn delete_user(&self, username: &str) -> Result<()> {
        SqliteUserRepository::delete_user(self, username).await
    }
}
