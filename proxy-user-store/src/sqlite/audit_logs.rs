use super::*;

const MAX_AUDIT_QUERY_LIMIT: u32 = 500;
const MAX_AUDIT_SEARCH_CHARACTERS: usize = 120;

pub(super) async fn insert_audit_event(
    transaction: &mut Transaction<'_, Sqlite>,
    event: NewAuditEvent,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO operation_audits \
         (action, actor_account_id, actor_login_name, target_kind, target_id, target_name, \
          context_id, reason, previous_value, new_value, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(event.action.as_str())
    .bind(event.actor_account_id)
    .bind(event.actor_login_name)
    .bind(event.target_kind.as_str())
    .bind(event.target_id)
    .bind(event.target_name)
    .bind(event.context_id)
    .bind(event.reason)
    .bind(event.previous_value)
    .bind(event.new_value)
    .bind(event.created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn row_to_audit_event(row: SqliteRow) -> Result<AuditEvent> {
    let action: String = row.try_get("action")?;
    let target_kind: String = row.try_get("target_kind")?;
    Ok(AuditEvent {
        audit_id: row.try_get("audit_id")?,
        action: AuditAction::parse(&action).ok_or_else(|| {
            UserRepositoryError::InvalidSchema(format!("未知审计操作类型：{action}"))
        })?,
        actor_account_id: row.try_get("actor_account_id")?,
        actor_login_name: row.try_get("actor_login_name")?,
        target_kind: AuditTargetKind::parse(&target_kind).ok_or_else(|| {
            UserRepositoryError::InvalidSchema(format!("未知审计目标类型：{target_kind}"))
        })?,
        target_id: row.try_get("target_id")?,
        target_name: row.try_get("target_name")?,
        context_id: row.try_get("context_id")?,
        reason: row.try_get("reason")?,
        previous_value: row.try_get("previous_value")?,
        new_value: row.try_get("new_value")?,
        created_at: row.try_get("created_at")?,
    })
}

#[async_trait]
impl AuditLogRepository for SqliteUserRepository {
    async fn list_audit_events(&self, query: AuditEventQuery) -> Result<Vec<AuditEvent>> {
        let limit = query.limit.clamp(1, MAX_AUDIT_QUERY_LIMIT);
        let search = query
            .search
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if search.is_some_and(|value| value.chars().count() > MAX_AUDIT_SEARCH_CHARACTERS) {
            return Err(ValidationError::InvalidAccountField(format!(
                "审计搜索关键字不能超过 {MAX_AUDIT_SEARCH_CHARACTERS} 个字符"
            ))
            .into());
        }

        let mut builder = QueryBuilder::<Sqlite>::new(
            "SELECT audit_id, action, actor_account_id, actor_login_name, target_kind, \
             target_id, target_name, context_id, reason, previous_value, new_value, created_at \
             FROM operation_audits WHERE 1 = 1",
        );
        if let Some(before) = query.before_audit_id.filter(|value| *value > 0) {
            builder.push(" AND audit_id < ").push_bind(before);
        }
        if let Some(action) = query.action {
            builder.push(" AND action = ").push_bind(action.as_str());
        }
        if let Some(search) = search {
            let pattern = format!("%{}%", escape_like(search));
            builder.push(" AND (actor_login_name LIKE ");
            builder.push_bind(pattern.clone());
            builder.push(" ESCAPE '\\' OR actor_account_id LIKE ");
            builder.push_bind(pattern.clone());
            builder.push(" ESCAPE '\\' OR target_name LIKE ");
            builder.push_bind(pattern.clone());
            builder.push(" ESCAPE '\\' OR target_id LIKE ");
            builder.push_bind(pattern.clone());
            builder.push(" ESCAPE '\\' OR COALESCE(reason, '') LIKE ");
            builder.push_bind(pattern.clone());
            builder.push(" ESCAPE '\\' OR COALESCE(context_id, '') LIKE ");
            builder.push_bind(pattern);
            builder.push(" ESCAPE '\\')");
        }
        builder
            .push(" ORDER BY audit_id DESC LIMIT ")
            .push_bind(i64::from(limit));
        let rows = builder.build().fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_audit_event).collect()
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}
