use super::*;

mod create;
mod decision;
mod poll;

#[async_trait]
impl AgentDeviceAuthorizationRepository for SqliteUserRepository {
    async fn create_agent_device_authorization(
        &self,
        authorization: NewAgentDeviceAuthorization,
    ) -> Result<()> {
        SqliteUserRepository::create_agent_device_authorization(self, authorization).await
    }

    async fn get_agent_device_authorization_by_user_code(
        &self,
        user_code_hash: &str,
        now: i64,
    ) -> Result<Option<AgentDeviceAuthorization>> {
        SqliteUserRepository::get_agent_device_authorization_by_user_code(self, user_code_hash, now)
            .await
    }

    async fn authorize_agent_device(
        &self,
        user_code_hash: &str,
        account_id: &str,
        account_auth_version: i64,
        now: i64,
    ) -> Result<AgentDeviceAuthorizationDecision> {
        SqliteUserRepository::authorize_agent_device(
            self,
            user_code_hash,
            account_id,
            account_auth_version,
            now,
        )
        .await
    }

    async fn deny_agent_device(
        &self,
        user_code_hash: &str,
        account_id: &str,
        now: i64,
    ) -> Result<AgentDeviceAuthorizationDecision> {
        SqliteUserRepository::deny_agent_device(self, user_code_hash, account_id, now).await
    }

    async fn poll_agent_device_authorization(
        &self,
        device_code_hash: &str,
        now: i64,
        minimum_interval_seconds: u32,
    ) -> Result<AgentDeviceAuthorizationPoll> {
        SqliteUserRepository::poll_agent_device_authorization(
            self,
            device_code_hash,
            now,
            minimum_interval_seconds,
        )
        .await
    }

    async fn finalize_agent_device_authorization(
        &self,
        claim: AgentDeviceAuthorizationClaim,
    ) -> Result<AgentDeviceAuthorizationFinalize> {
        SqliteUserRepository::finalize_agent_device_authorization(self, claim).await
    }
}
