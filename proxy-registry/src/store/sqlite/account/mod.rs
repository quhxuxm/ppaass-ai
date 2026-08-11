use super::*;

mod binding_and_queries;
mod creation;
mod key_operations;
mod password;
mod request_approval;
mod request_rejection;
mod request_submission;
mod selection;
mod updates;

#[async_trait]
impl AccountRepository for SqliteUserRepository {
    async fn key_encryption_binding(&self) -> Result<KeyEncryptionBinding> {
        SqliteUserRepository::key_encryption_binding(self).await
    }

    async fn initialize_key_encryption_verifier(&self, verifier: &str) -> Result<String> {
        SqliteUserRepository::initialize_key_encryption_verifier(self, verifier).await
    }

    async fn bootstrap_admin_if_absent(&self, admin: NewAdminAccount) -> Result<BootstrapOutcome> {
        SqliteUserRepository::bootstrap_admin_if_absent(self, admin).await
    }

    async fn get_account_by_login(&self, login_name: &str) -> Result<Option<WebAccount>> {
        SqliteUserRepository::get_account_by_login(self, login_name).await
    }

    async fn get_account_by_id(&self, account_id: &str) -> Result<Option<WebAccount>> {
        SqliteUserRepository::get_account_by_id(self, account_id).await
    }

    async fn get_account_by_external(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<WebAccount>> {
        SqliteUserRepository::get_account_by_external(self, provider, subject).await
    }

    async fn get_login_record(&self, login_name: &str) -> Result<Option<LoginRecord>> {
        SqliteUserRepository::get_login_record(self, login_name).await
    }

    async fn update_password_hash(
        &self,
        account_id: &str,
        expected_auth_version: i64,
        password_hash: String,
    ) -> Result<WebAccount> {
        SqliteUserRepository::update_password_hash(
            self,
            account_id,
            expected_auth_version,
            password_hash,
        )
        .await
    }

    async fn list_managed_users(&self) -> Result<Vec<ManagedUser>> {
        SqliteUserRepository::list_managed_users(self).await
    }

    async fn get_managed_user(&self, account_id: &str) -> Result<Option<ManagedUser>> {
        SqliteUserRepository::get_managed_user(self, account_id).await
    }

    async fn get_managed_user_by_username(&self, username: &str) -> Result<Option<ManagedUser>> {
        SqliteUserRepository::get_managed_user_by_username(self, username).await
    }

    async fn create_managed_user(&self, user: NewManagedUser) -> Result<ManagedUser> {
        SqliteUserRepository::create_managed_user(self, user).await
    }

    async fn create_user_account(&self, account: NewUserAccount) -> Result<WebAccount> {
        SqliteUserRepository::create_user_account(self, account).await
    }

    async fn update_managed_user(
        &self,
        account_id: &str,
        update: ManagedUserUpdate,
    ) -> Result<ManagedUser> {
        SqliteUserRepository::update_managed_user(self, account_id, update).await
    }

    async fn select_proxy_address(
        &self,
        account_id: &str,
        proxy_address_id: &str,
        required_permission: &str,
    ) -> Result<ManagedUser> {
        SqliteUserRepository::select_proxy_address(
            self,
            account_id,
            proxy_address_id,
            required_permission,
        )
        .await
    }

    async fn update_last_login(&self, account_id: &str, logged_in_at: i64) -> Result<()> {
        SqliteUserRepository::update_last_login(self, account_id, logged_in_at).await
    }

    async fn load_encrypted_private_key(
        &self,
        username: &str,
    ) -> Result<Option<EncryptedPrivateKey>> {
        SqliteUserRepository::load_encrypted_private_key(self, username).await
    }

    async fn rotate_keypair(&self, rotation: KeyPairRotation) -> Result<UserRecord> {
        SqliteUserRepository::rotate_keypair(self, rotation).await
    }

    async fn submit_key_generation_request(
        &self,
        request: NewKeyGenerationRequest,
    ) -> Result<KeyGenerationRequest> {
        SqliteUserRepository::submit_key_generation_request(self, request).await
    }

    async fn get_pending_key_generation_request(
        &self,
        account_id: &str,
    ) -> Result<Option<KeyGenerationRequest>> {
        SqliteUserRepository::get_pending_key_generation_request(self, account_id).await
    }

    async fn get_key_generation_request(
        &self,
        request_id: &str,
    ) -> Result<Option<KeyGenerationRequest>> {
        SqliteUserRepository::get_key_generation_request(self, request_id).await
    }

    async fn get_latest_key_generation_request(
        &self,
        account_id: &str,
    ) -> Result<Option<KeyGenerationRequest>> {
        SqliteUserRepository::get_latest_key_generation_request(self, account_id).await
    }

    async fn list_pending_key_generation_requests(&self) -> Result<Vec<KeyGenerationRequest>> {
        SqliteUserRepository::list_pending_key_generation_requests(self).await
    }

    async fn approve_key_generation_request(
        &self,
        approval: KeyRequestApproval,
    ) -> Result<KeyRequestApprovalResult> {
        SqliteUserRepository::approve_key_generation_request(self, approval).await
    }

    async fn reject_key_generation_request(
        &self,
        rejection: KeyRequestRejection,
    ) -> Result<KeyGenerationRequest> {
        SqliteUserRepository::reject_key_generation_request(self, rejection).await
    }

    async fn delete_managed_user(&self, account_id: &str) -> Result<()> {
        SqliteUserRepository::delete_managed_user(self, account_id).await
    }

    async fn active_admin_count(&self) -> Result<u64> {
        SqliteUserRepository::active_admin_count(self).await
    }
}
