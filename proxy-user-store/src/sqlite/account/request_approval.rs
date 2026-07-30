use super::super::*;

impl SqliteUserRepository {
    #[instrument(
        skip(self, approval),
        fields(
            request_id = %approval.request_id,
            reviewer_account_id = %approval.reviewer_account_id
        )
    )]
    pub(super) async fn approve_key_generation_request(
        &self,
        approval: KeyRequestApproval,
    ) -> Result<KeyRequestApprovalResult> {
        let KeyRequestApproval {
            request_id,
            reviewer_account_id,
            expires_at,
            proxy_address_ids,
            material,
            audit_reason,
        } = approval;
        let request_id = normalize_request_id(&request_id)?;
        let reviewer_account_id = normalize_account_id(&reviewer_account_id)?;
        let proxy_address_ids = normalize_proxy_address_ids(&proxy_address_ids)?;
        let audit_reason = normalize_audit_reason(&audit_reason)?;

        let material = match material {
            ApprovedKeyMaterial::Initial {
                mut profile,
                encrypted_private_key,
            } => {
                profile.expires_at = Some(expires_at);
                let profile = normalize_new_user(profile)?;
                validate_private_key_envelope(&encrypted_private_key)?;
                ApprovedKeyMaterial::Initial {
                    profile,
                    encrypted_private_key,
                }
            }
            ApprovedKeyMaterial::Rotate {
                public_key_pem,
                encrypted_private_key,
            } => {
                let public_key_pem = normalize_public_key_pem(&public_key_pem)?;
                validate_private_key_envelope(&encrypted_private_key)?;
                ApprovedKeyMaterial::Rotate {
                    public_key_pem,
                    encrypted_private_key,
                }
            }
        };

        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        // 必须在取得写锁后判断，避免等待锁期间过期时间已经越过当前时刻。
        let timestamp = now();
        if expires_at <= timestamp {
            return Err(UserRepositoryError::InvalidApprovalExpiration {
                expires_at,
                now: timestamp,
            });
        }
        let request = fetch_key_request_by_id(&mut transaction, &request_id)
            .await?
            .ok_or_else(|| UserRepositoryError::KeyRequestNotFound(request_id.clone()))?;
        if request.status != KeyRequestStatus::Pending {
            return Err(UserRepositoryError::KeyRequestAlreadyReviewed {
                request_id,
                status: request.status,
            });
        }
        let reviewer = fetch_account_by_id(&mut transaction, &reviewer_account_id)
            .await?
            .ok_or_else(|| UserRepositoryError::NotFound(reviewer_account_id.clone()))?;
        ensure_active_admin(&reviewer)?;
        let mut account = fetch_account_by_id(&mut transaction, &request.account_id)
            .await?
            .ok_or_else(|| UserRepositoryError::NotFound(request.account_id.clone()))?;
        ensure_active_key_account(&account)?;

        match (request.kind, material) {
            (
                KeyRequestKind::Initial,
                ApprovedKeyMaterial::Initial {
                    profile,
                    encrypted_private_key,
                },
            ) => {
                if account.linked_username.is_some() {
                    return Err(UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: "账号已经关联 Proxy 用户".to_string(),
                    });
                }
                if !profile.enabled {
                    return Err(UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: "初始审批不能创建停用的 Proxy 用户".to_string(),
                    });
                }
                let profile_exists: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)")
                        .bind(&profile.username)
                        .fetch_one(&mut *transaction)
                        .await?;
                if profile_exists {
                    return Err(UserRepositoryError::Conflict(profile.username));
                }
                insert_profile(&mut transaction, &profile, timestamp).await?;
                sqlx::query(
                    "UPDATE web_accounts SET linked_username = ?, updated_at = ? \
                     WHERE account_id = ? AND linked_username IS NULL",
                )
                .bind(&profile.username)
                .bind(timestamp)
                .bind(&account.account_id)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "INSERT INTO user_private_keys \
                     (username, encrypted_private_key, key_version, updated_at) \
                     VALUES (?, ?, 1, ?)",
                )
                .bind(&profile.username)
                .bind(encrypted_private_key)
                .bind(timestamp)
                .execute(&mut *transaction)
                .await?;
                account.linked_username = Some(profile.username);
                account.updated_at = timestamp;
            }
            (
                KeyRequestKind::Rotate,
                ApprovedKeyMaterial::Rotate {
                    public_key_pem,
                    encrypted_private_key,
                },
            ) => {
                let username = account.linked_username.as_deref().ok_or_else(|| {
                    UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: "账号不再关联 Proxy 用户".to_string(),
                    }
                })?;
                let profile = fetch_profile(&mut transaction, username)
                    .await?
                    .ok_or_else(|| {
                        UserRepositoryError::InvalidSchema(format!(
                            "账号 {} 关联的用户 {username} 不存在",
                            account.account_id
                        ))
                    })?;
                if !profile.enabled {
                    return Err(UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: "Proxy 用户已在申请后被停用".to_string(),
                    });
                }
                let expected = request.expected_key_version.ok_or_else(|| {
                    UserRepositoryError::InvalidSchema(format!(
                        "轮换申请 {} 缺少 expected_key_version",
                        request.request_id
                    ))
                })?;
                if profile.key_version != expected {
                    return Err(UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: format!(
                            "密钥版本已变化，期望 {expected}，实际 {}",
                            profile.key_version
                        ),
                    });
                }
                let new_version = expected.checked_add(1).ok_or_else(|| {
                    UserRepositoryError::InvalidSchema(format!(
                        "用户 {username} 的 key_version 已溢出"
                    ))
                })?;
                let result = sqlx::query(
                    "UPDATE users SET public_key_pem = ?, key_version = ?, expires_at = ?, \
                     updated_at = ? WHERE username = ? AND key_version = ?",
                )
                .bind(public_key_pem)
                .bind(new_version)
                .bind(expires_at)
                .bind(timestamp)
                .bind(username)
                .bind(expected)
                .execute(&mut *transaction)
                .await?;
                if result.rows_affected() != 1 {
                    return Err(UserRepositoryError::StaleKeyRequest {
                        request_id: request.request_id.clone(),
                        reason: "密钥版本在审批期间发生变化".to_string(),
                    });
                }
                sqlx::query(
                    "INSERT INTO user_private_keys \
                     (username, encrypted_private_key, key_version, updated_at) VALUES (?, ?, ?, ?) \
                     ON CONFLICT(username) DO UPDATE SET \
                         encrypted_private_key = excluded.encrypted_private_key, \
                         key_version = excluded.key_version, \
                         updated_at = excluded.updated_at",
                )
                .bind(username)
                .bind(encrypted_private_key)
                .bind(new_version)
                .bind(timestamp)
                .execute(&mut *transaction)
                .await?;
            }
            (kind, _) => {
                return Err(UserRepositoryError::StaleKeyRequest {
                    request_id: request.request_id.clone(),
                    reason: format!("审批材料与 {} 申请不匹配", kind.as_str()),
                });
            }
        }

        let result = sqlx::query(
            "UPDATE key_generation_requests SET status = 'approved', \
             reviewer_account_id = ?, reviewer_login_name = ?, rejection_reason = NULL, \
             reviewed_at = ?, approved_expires_at = ? \
             WHERE request_id = ? AND status = 'pending'",
        )
        .bind(&reviewer.account_id)
        .bind(&reviewer.login_name)
        .bind(timestamp)
        .bind(expires_at)
        .bind(&request.request_id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(UserRepositoryError::KeyRequestAlreadyReviewed {
                request_id: request.request_id,
                status: KeyRequestStatus::Pending,
            });
        }
        insert_audit_event(
            &mut transaction,
            NewAuditEvent {
                action: AuditAction::KeyRequestApproved,
                actor_account_id: reviewer.account_id.clone(),
                actor_login_name: reviewer.login_name.clone(),
                target_kind: AuditTargetKind::User,
                target_id: account.account_id.clone(),
                target_name: account.login_name.clone(),
                context_id: Some(request.request_id.clone()),
                reason: Some(audit_reason.clone()),
                previous_value: Some("pending".to_string()),
                new_value: Some("approved".to_string()),
                created_at: timestamp,
            },
        )
        .await?;
        if request.kind == KeyRequestKind::Initial {
            let created_profile = fetch_profile(
                &mut transaction,
                account.linked_username.as_deref().ok_or_else(|| {
                    UserRepositoryError::InvalidSchema(
                        "初始密钥审批后账号未关联 Proxy 用户".to_string(),
                    )
                })?,
            )
            .await?
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema("初始密钥审批后 Proxy 用户不存在".to_string())
            })?;
            insert_audit_event(
                &mut transaction,
                NewAuditEvent {
                    action: AuditAction::ProxyAccessEnabled,
                    actor_account_id: reviewer.account_id.clone(),
                    actor_login_name: reviewer.login_name.clone(),
                    target_kind: AuditTargetKind::User,
                    target_id: account.account_id.clone(),
                    target_name: account.login_name.clone(),
                    context_id: Some(request.request_id.clone()),
                    reason: Some(audit_reason.clone()),
                    previous_value: None,
                    new_value: Some(created_profile.enabled.to_string()),
                    created_at: timestamp,
                },
            )
            .await?;
            insert_audit_event(
                &mut transaction,
                NewAuditEvent {
                    action: AuditAction::PermissionsUpdated,
                    actor_account_id: reviewer.account_id.clone(),
                    actor_login_name: reviewer.login_name.clone(),
                    target_kind: AuditTargetKind::User,
                    target_id: account.account_id.clone(),
                    target_name: account.login_name.clone(),
                    context_id: Some(request.request_id.clone()),
                    reason: Some(audit_reason),
                    previous_value: Some("[]".to_string()),
                    new_value: Some(
                        serde_json::to_string(&created_profile.permissions).map_err(|error| {
                            UserRepositoryError::InvalidSchema(error.to_string())
                        })?,
                    ),
                    created_at: timestamp,
                },
            )
            .await?;
        }
        replace_account_proxy_addresses(
            &mut transaction,
            &account.account_id,
            &proxy_address_ids,
            timestamp,
        )
        .await?;
        let request = fetch_key_request_by_id(&mut transaction, &request_id)
            .await?
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema(
                    "刚批准的 key_generation_requests 记录不可见".to_string(),
                )
            })?;
        let managed_user = fetch_managed_for_account(&mut transaction, account).await?;
        transaction.commit().await?;
        info!(
            request_id,
            reviewer_account_id,
            account_id = request.account_id,
            kind = request.kind.as_str(),
            "管理员已批准密钥申请"
        );
        Ok(KeyRequestApprovalResult {
            request,
            managed_user,
        })
    }
}
