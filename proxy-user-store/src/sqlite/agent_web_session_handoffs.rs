use super::*;

impl SqliteUserRepository {
    async fn create_agent_web_session_handoff_record(
        &self,
        handoff: NewAgentWebSessionHandoff,
        current_time: i64,
        maximum_entries: u32,
        maximum_entries_per_account: u32,
    ) -> Result<AgentWebSessionHandoffCreate> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("DELETE FROM agent_web_session_handoffs WHERE expires_at <= ?")
            .bind(current_time)
            .execute(&mut *transaction)
            .await?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_web_session_handoffs")
            .fetch_one(&mut *transaction)
            .await?;
        let account_total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_web_session_handoffs WHERE account_id = ?",
        )
        .bind(&handoff.account_id)
        .fetch_one(&mut *transaction)
        .await?;
        if total >= i64::from(maximum_entries)
            || account_total >= i64::from(maximum_entries_per_account)
        {
            transaction.commit().await?;
            return Ok(AgentWebSessionHandoffCreate::Capacity);
        }

        let exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_web_session_handoffs WHERE code_hash = ?",
        )
        .bind(&handoff.code_hash)
        .fetch_one(&mut *transaction)
        .await?;
        if exists != 0 {
            transaction.commit().await?;
            return Ok(AgentWebSessionHandoffCreate::Conflict);
        }

        sqlx::query(
            "INSERT INTO agent_web_session_handoffs \
             (code_hash, account_id, account_auth_version, expires_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(handoff.code_hash)
        .bind(handoff.account_id)
        .bind(handoff.account_auth_version)
        .bind(handoff.expires_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(AgentWebSessionHandoffCreate::Created)
    }

    async fn consume_agent_web_session_handoff_record(
        &self,
        code_hash: &str,
        current_time: i64,
    ) -> Result<AgentWebSessionHandoffConsume> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query(
            "SELECT account_id, account_auth_version, expires_at \
             FROM agent_web_session_handoffs WHERE code_hash = ?",
        )
        .bind(code_hash)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.rollback().await?;
            return Ok(AgentWebSessionHandoffConsume::NotFound);
        };

        sqlx::query("DELETE FROM agent_web_session_handoffs WHERE code_hash = ?")
            .bind(code_hash)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;

        let expires_at: i64 = row.try_get("expires_at")?;
        if expires_at <= current_time {
            return Ok(AgentWebSessionHandoffConsume::Expired);
        }
        Ok(AgentWebSessionHandoffConsume::Claimed {
            account_id: row.try_get("account_id")?,
            account_auth_version: row.try_get("account_auth_version")?,
        })
    }
}

#[async_trait]
impl AgentWebSessionHandoffRepository for SqliteUserRepository {
    async fn create_agent_web_session_handoff(
        &self,
        handoff: NewAgentWebSessionHandoff,
        now: i64,
        maximum_entries: u32,
        maximum_entries_per_account: u32,
    ) -> Result<AgentWebSessionHandoffCreate> {
        self.create_agent_web_session_handoff_record(
            handoff,
            now,
            maximum_entries,
            maximum_entries_per_account,
        )
        .await
    }

    async fn consume_agent_web_session_handoff(
        &self,
        code_hash: &str,
        now: i64,
    ) -> Result<AgentWebSessionHandoffConsume> {
        self.consume_agent_web_session_handoff_record(code_hash, now)
            .await
    }
}
