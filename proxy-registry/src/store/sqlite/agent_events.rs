use super::*;
use crate::{AgentEventRecord, AgentEventRepository};

const MAX_AGENT_EVENT_BATCH_SIZE: u32 = 1_024;

pub(super) const PROFILE_CHANGED_EVENT: &str = "profile_changed";
pub(super) const PROFILES_CHANGED_EVENT: &str = "profiles_changed";
pub(super) const KEY_REQUEST_CHANGED_EVENT: &str = "key_request_changed";
pub(super) const ADMIN_KEY_REQUESTS_CHANGED_EVENT: &str = "admin_key_requests_changed";

pub(super) async fn insert_agent_event(
    transaction: &mut Transaction<'_, Sqlite>,
    kind: &str,
    account_id: Option<&str>,
    created_at: i64,
) -> Result<()> {
    sqlx::query("INSERT INTO registry_agent_events(kind, account_id, created_at) VALUES (?, ?, ?)")
        .bind(kind)
        .bind(account_id)
        .bind(created_at)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

impl SqliteUserRepository {
    async fn latest_agent_event_revision(&self) -> Result<u64> {
        let revision: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(event_id), 0) FROM registry_agent_events")
                .fetch_one(&self.pool)
                .await?;
        u64::try_from(revision).map_err(|_| {
            UserRepositoryError::InvalidSchema(
                "registry_agent_events.event_id 不能表示为非负修订号".to_string(),
            )
        })
    }

    async fn list_agent_events_after(
        &self,
        revision: u64,
        limit: u32,
    ) -> Result<Vec<AgentEventRecord>> {
        let revision = i64::try_from(revision).map_err(|_| {
            UserRepositoryError::InvalidSchema("Agent 事件读取游标超出 SQLite 范围".to_string())
        })?;
        let limit = i64::from(limit.clamp(1, MAX_AGENT_EVENT_BATCH_SIZE));
        let rows = sqlx::query(
            "SELECT event_id, kind, account_id FROM registry_agent_events \
             WHERE event_id > ? ORDER BY event_id LIMIT ?",
        )
        .bind(revision)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let revision: i64 = row.try_get("event_id")?;
                Ok(AgentEventRecord {
                    revision: u64::try_from(revision).map_err(|_| {
                        UserRepositoryError::InvalidSchema(
                            "registry_agent_events.event_id 不能表示为非负修订号".to_string(),
                        )
                    })?,
                    kind: row.try_get("kind")?,
                    account_id: row.try_get("account_id")?,
                })
            })
            .collect()
    }

    async fn purge_agent_events_before(&self, before: i64) -> Result<u64> {
        let mut transaction = self.pool.begin().await?;
        let latest: Option<i64> =
            sqlx::query_scalar("SELECT MAX(event_id) FROM registry_agent_events")
                .fetch_one(&mut *transaction)
                .await?;
        let Some(latest) = latest else {
            transaction.commit().await?;
            return Ok(0);
        };
        let result =
            sqlx::query("DELETE FROM registry_agent_events WHERE created_at < ? AND event_id < ?")
                .bind(before)
                .bind(latest)
                .execute(&mut *transaction)
                .await?;
        let removed = result.rows_affected();
        transaction.commit().await?;
        Ok(removed)
    }
}

#[async_trait]
impl AgentEventRepository for SqliteUserRepository {
    async fn latest_agent_event_revision(&self) -> Result<u64> {
        SqliteUserRepository::latest_agent_event_revision(self).await
    }

    async fn list_agent_events_after(
        &self,
        revision: u64,
        limit: u32,
    ) -> Result<Vec<AgentEventRecord>> {
        SqliteUserRepository::list_agent_events_after(self, revision, limit).await
    }

    async fn purge_agent_events_before(&self, before: i64) -> Result<u64> {
        SqliteUserRepository::purge_agent_events_before(self, before).await
    }
}
