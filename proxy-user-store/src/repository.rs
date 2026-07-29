use async_trait::async_trait;

use crate::{
    AccessLogSettings, AccessRecord, AgentDeviceAuthorization, AgentDeviceAuthorizationClaim,
    AgentDeviceAuthorizationDecision, AgentDeviceAuthorizationFinalize,
    AgentDeviceAuthorizationPoll, BootstrapOutcome, EncryptedPrivateKey, KeyEncryptionBinding,
    KeyGenerationRequest, KeyPairRotation, KeyRequestApproval, KeyRequestApprovalResult,
    LoginRecord, ManagedUser, ManagedUserUpdate, NewAccessRecord, NewAdminAccount,
    NewAgentDeviceAuthorization, NewKeyGenerationRequest, NewManagedUser, NewUserAccount, Result,
    UserRecord, UserUpdate, WebAccount,
};

/// 数据库无关的用户 CRUD 接口。
///
/// Proxy 认证与 Web API 只依赖该接口；SQLite、PostgreSQL 等后端由各自适配器实现。
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn get_user(&self, username: &str) -> Result<Option<UserRecord>>;

    async fn list_users(&self) -> Result<Vec<UserRecord>>;

    async fn create_user(
        &self,
        username: &str,
        public_key_pem: &str,
        expires_at: Option<i64>,
    ) -> Result<UserRecord>;

    async fn update_user(&self, username: &str, update: UserUpdate) -> Result<UserRecord>;

    async fn delete_user(&self, username: &str) -> Result<()>;
}

/// Web 账号、托管用户和私钥信封的数据库无关接口。
///
/// 接口只表达领域操作与原子性要求，不暴露 SQLite 的连接、事务或 SQL 类型。
#[async_trait]
pub trait AccountRepository: Send + Sync {
    /// 读取数据库绑定的主密钥校验值及任意一个可用于验证解密的私钥信封。
    async fn key_encryption_binding(&self) -> Result<KeyEncryptionBinding>;

    /// 仅在尚未绑定时写入主密钥校验值，并始终返回数据库中的实际值。
    async fn initialize_key_encryption_verifier(&self, verifier: &str) -> Result<String>;

    /// 当指定登录名不存在时原子创建 bootstrap 管理员。
    async fn bootstrap_admin_if_absent(&self, admin: NewAdminAccount) -> Result<BootstrapOutcome>;

    async fn get_account_by_login(&self, login_name: &str) -> Result<Option<WebAccount>>;

    async fn get_account_by_id(&self, account_id: &str) -> Result<Option<WebAccount>>;

    async fn get_account_by_external(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<WebAccount>>;

    /// 登录校验专用查询；返回值含密码哈希，调用方不得记录。
    async fn get_login_record(&self, login_name: &str) -> Result<Option<LoginRecord>>;

    /// 以账号认证版本为 CAS 条件更新密码哈希，并递增认证版本。
    ///
    /// 调用方必须先校验当前密码；存储层只负责原子替换哈希，绝不接触明文密码。
    async fn update_password_hash(
        &self,
        account_id: &str,
        expected_auth_version: i64,
        password_hash: String,
    ) -> Result<WebAccount>;

    /// 同时列出有 Web 账号的托管用户与数据库中保留的历史 legacy 用户。
    async fn list_managed_users(&self) -> Result<Vec<ManagedUser>>;

    async fn get_managed_user(&self, account_id: &str) -> Result<Option<ManagedUser>>;

    async fn get_managed_user_by_username(&self, username: &str) -> Result<Option<ManagedUser>>;

    /// 原子创建账号、Proxy profile、私钥信封及可选外部身份。
    async fn create_managed_user(&self, user: NewManagedUser) -> Result<ManagedUser>;

    /// 原子创建尚未关联 Proxy profile 的启用普通账号及可选外部身份。
    async fn create_user_account(&self, account: NewUserAccount) -> Result<WebAccount>;

    /// 原子更新账号资料及其关联的 Proxy profile。
    async fn update_managed_user(
        &self,
        account_id: &str,
        update: ManagedUserUpdate,
    ) -> Result<ManagedUser>;

    async fn update_last_login(&self, account_id: &str, logged_in_at: i64) -> Result<()>;

    /// 读取加密后的私钥信封；明文解密由 Web 服务负责。
    async fn load_encrypted_private_key(
        &self,
        username: &str,
    ) -> Result<Option<EncryptedPrivateKey>>;

    /// 以 profile 的 `key_version` 为 CAS 条件原子轮换公钥和私钥信封。
    async fn rotate_keypair(&self, rotation: KeyPairRotation) -> Result<UserRecord>;

    /// 为启用的用户或管理员账号提交密钥申请；类型和期望版本由存储层按当前状态推导。
    async fn submit_key_generation_request(
        &self,
        request: NewKeyGenerationRequest,
    ) -> Result<KeyGenerationRequest>;

    /// 查询账号当前的待审批申请。
    async fn get_pending_key_generation_request(
        &self,
        account_id: &str,
    ) -> Result<Option<KeyGenerationRequest>>;

    /// 按稳定申请 ID 查询任意状态的申请。
    async fn get_key_generation_request(
        &self,
        request_id: &str,
    ) -> Result<Option<KeyGenerationRequest>>;

    /// 按申请时间列出所有待审批申请。
    async fn list_pending_key_generation_requests(&self) -> Result<Vec<KeyGenerationRequest>>;

    /// 原子批准申请、写入新密钥材料、更新/创建 profile 并完成账号关联。
    async fn approve_key_generation_request(
        &self,
        approval: KeyRequestApproval,
    ) -> Result<KeyRequestApprovalResult>;

    /// 管理员拒绝一项仍处于 pending 的申请。
    async fn reject_key_generation_request(
        &self,
        request_id: &str,
        reviewer_account_id: &str,
    ) -> Result<KeyGenerationRequest>;

    /// 仅当账号已经停用时，原子删除 Web 账号及其关联的 Proxy profile。
    async fn delete_managed_user(&self, account_id: &str) -> Result<()>;

    async fn active_admin_count(&self) -> Result<u64>;
}

/// Proxy 访问记录及其保留策略的数据库无关接口。
#[async_trait]
pub trait AccessLogRepository: Send + Sync {
    /// 原子记录一次已通过认证的 Proxy 访问。同一用户和目标地址只保留一行，
    /// 重复访问累加次数并刷新最近访问信息。
    async fn record_access(&self, record: NewAccessRecord) -> Result<()>;

    /// 查询用户自 `since`（含）起的最近访问，按时间倒序返回。
    async fn list_recent_access(
        &self,
        username: &str,
        since: i64,
        limit: u32,
    ) -> Result<Vec<AccessRecord>>;

    async fn get_access_log_settings(&self) -> Result<AccessLogSettings>;

    async fn set_access_log_retention_days(&self, retention_days: u16)
    -> Result<AccessLogSettings>;

    /// 删除早于 `before` 的记录并返回删除数量。
    async fn purge_access_records_before(&self, before: i64) -> Result<u64>;
}

/// Agent 浏览器设备授权的数据库无关接口。
///
/// 原始设备码和用户短码永远不进入该接口；调用方只能传入带域分隔的摘要。
#[async_trait]
pub trait AgentDeviceAuthorizationRepository: Send + Sync {
    async fn create_agent_device_authorization(
        &self,
        authorization: NewAgentDeviceAuthorization,
    ) -> Result<()>;

    async fn get_agent_device_authorization_by_user_code(
        &self,
        user_code_hash: &str,
        now: i64,
    ) -> Result<Option<AgentDeviceAuthorization>>;

    async fn authorize_agent_device(
        &self,
        user_code_hash: &str,
        account_id: &str,
        account_auth_version: i64,
        now: i64,
    ) -> Result<AgentDeviceAuthorizationDecision>;

    async fn deny_agent_device(
        &self,
        user_code_hash: &str,
        account_id: &str,
        now: i64,
    ) -> Result<AgentDeviceAuthorizationDecision>;

    /// 原子执行轮询限频；已消费的 challenge 不再返回账号快照。
    async fn poll_agent_device_authorization(
        &self,
        device_code_hash: &str,
        now: i64,
        minimum_interval_seconds: u32,
    ) -> Result<AgentDeviceAuthorizationPoll>;

    /// 在响应已成功构造后，以账号快照为 CAS 条件把 challenge 标记为已领取。
    ///
    /// 同一 device code 的后续重试返回 `AlreadyFinalized` 并必须被调用方拒绝。
    async fn finalize_agent_device_authorization(
        &self,
        claim: AgentDeviceAuthorizationClaim,
    ) -> Result<AgentDeviceAuthorizationFinalize>;
}
