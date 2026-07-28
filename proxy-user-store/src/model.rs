use serde::{Deserialize, Serialize};

pub const PROXY_CONNECT_TCP_PERMISSION: &str = "proxy.connect.tcp";
pub const PROXY_CONNECT_UDP_PERMISSION: &str = "proxy.connect.udp";

pub fn default_proxy_permissions() -> Vec<String> {
    vec![
        PROXY_CONNECT_TCP_PERMISSION.to_string(),
        PROXY_CONNECT_UDP_PERMISSION.to_string(),
    ]
}

pub const DEFAULT_ACCESS_LOG_RETENTION_DAYS: u16 = 7;
pub const MIN_ACCESS_LOG_RETENTION_DAYS: u16 = 1;
pub const MAX_ACCESS_LOG_RETENTION_DAYS: u16 = 365;
pub const MAX_ACCESS_LOG_QUERY_LIMIT: u32 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserOrigin {
    Local,
    Google,
    Wechat,
    Admin,
    Legacy,
}

impl UserOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Google => "google",
            Self::Wechat => "wechat",
            Self::Admin => "admin",
            Self::Legacy => "legacy",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "local" => Some(Self::Local),
            "google" => Some(Self::Google),
            "wechat" => Some(Self::Wechat),
            "admin" => Some(Self::Admin),
            "legacy" => Some(Self::Legacy),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    pub username: String,
    pub public_key_pem: String,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub origin: UserOrigin,
    pub key_version: i64,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    pub username: String,
    pub public_key_pem: String,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub origin: UserOrigin,
    pub expires_at: Option<i64>,
}

impl NewUser {
    pub fn new(
        username: impl Into<String>,
        public_key_pem: impl Into<String>,
        origin: UserOrigin,
    ) -> Self {
        Self {
            username: username.into(),
            public_key_pem: public_key_pem.into(),
            permissions: default_proxy_permissions(),
            enabled: true,
            origin,
            expires_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserUpdate {
    pub public_key_pem: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub enabled: Option<bool>,
    /// `None` 表示不修改，`Some(None)` 表示清除过期时间。
    pub expires_at: Option<Option<i64>>,
}

impl UserUpdate {
    pub fn is_empty(&self) -> bool {
        self.public_key_pem.is_none()
            && self.permissions.is_none()
            && self.enabled.is_none()
            && self.expires_at.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountRole {
    Admin,
    User,
}

impl AccountRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Self::Admin),
            "user" => Some(Self::User),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Active,
    Disabled,
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAccount {
    pub account_id: String,
    pub login_name: String,
    pub role: AccountRole,
    pub status: AccountStatus,
    pub linked_username: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub auth_version: i64,
    pub last_login_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalIdentity {
    pub provider: String,
    pub subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedUser {
    pub account: Option<WebAccount>,
    pub profile: Option<UserRecord>,
    pub has_private_key: bool,
    pub providers: Vec<ExternalIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManagedUserUpdate {
    pub role: Option<AccountRole>,
    pub status: Option<AccountStatus>,
    pub enabled: Option<bool>,
    pub permissions: Option<Vec<String>>,
    pub expires_at: Option<Option<i64>>,
    pub display_name: Option<Option<String>>,
    pub email: Option<Option<String>>,
    pub avatar_url: Option<Option<String>>,
}

impl ManagedUserUpdate {
    pub fn is_empty(&self) -> bool {
        self.role.is_none()
            && self.status.is_none()
            && self.enabled.is_none()
            && self.permissions.is_none()
            && self.expires_at.is_none()
            && self.display_name.is_none()
            && self.email.is_none()
            && self.avatar_url.is_none()
    }
}

/// 登录校验专用记录。包含密码哈希，因此故意不实现 `Debug` 或序列化。
pub struct LoginRecord {
    pub account: WebAccount,
    pub password_hash: Option<String>,
}

/// 数据库存储的私钥信封。包含密文，因此故意不实现 `Debug` 或序列化。
pub struct EncryptedPrivateKey {
    pub username: String,
    pub encrypted_private_key: Vec<u8>,
    pub key_version: i64,
    pub updated_at: i64,
}

/// 私钥加密主密钥与数据库的持久绑定状态。
///
/// 样本包含私钥密文，因此该类型故意不实现 `Debug` 或序列化。
pub struct KeyEncryptionBinding {
    pub verifier: Option<String>,
    pub sample_private_key: Option<EncryptedPrivateKey>,
}

/// 管理端或注册流程一次性创建账号、Proxy profile 和托管私钥。
///
/// 该类型携带密码哈希与私钥密文，因此故意不实现 `Debug` 或序列化。
pub struct NewManagedUser {
    pub account_id: String,
    pub login_name: String,
    pub password_hash: Option<String>,
    pub role: AccountRole,
    pub status: AccountStatus,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub profile: NewUser,
    pub encrypted_private_key: Vec<u8>,
    pub external_identity: Option<ExternalIdentity>,
}

/// 首次启动创建管理员账号所需的数据。管理员可以不绑定 Proxy profile。
///
/// 该类型携带密码哈希，因此故意不实现 `Debug` 或序列化。
pub struct NewAdminAccount {
    pub account_id: String,
    pub login_name: String,
    pub password_hash: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
}

/// 尚未获批 Proxy 密钥的普通 Web 账号。
///
/// 该类型携带密码哈希，因此故意不实现 `Debug` 或序列化。账号固定以启用的普通用户
/// 身份创建，审批密钥申请后才会关联 Proxy profile。
pub struct NewUserAccount {
    pub account_id: String,
    pub login_name: String,
    pub password_hash: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub external_identity: Option<ExternalIdentity>,
}

/// 托管 RSA 密钥对的原子轮换输入。
///
/// 该类型携带私钥密文，因此故意不实现 `Debug` 或序列化。
pub struct KeyPairRotation {
    pub username: String,
    pub expected_key_version: i64,
    pub public_key_pem: String,
    pub encrypted_private_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyRequestKind {
    Initial,
    Rotate,
}

impl KeyRequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Rotate => "rotate",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "initial" => Some(Self::Initial),
            "rotate" => Some(Self::Rotate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyRequestStatus {
    Pending,
    Approved,
    Rejected,
}

impl KeyRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// 普通用户的密钥生成或轮换申请。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyGenerationRequest {
    pub request_id: String,
    pub account_id: String,
    pub kind: KeyRequestKind,
    pub status: KeyRequestStatus,
    pub expected_key_version: Option<i64>,
    pub reviewer_account_id: Option<String>,
    pub requested_at: i64,
    pub reviewed_at: Option<i64>,
    pub approved_expires_at: Option<i64>,
}

/// 新建申请只接受稳定标识；申请类型和期望密钥版本由存储层按当前状态推导。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewKeyGenerationRequest {
    pub request_id: String,
    pub account_id: String,
}

/// 管理员批准申请时提交的密钥材料。
///
/// 私钥字段保存 Web 服务生成的加密信封，因此故意不实现 `Debug` 或序列化。
pub enum ApprovedKeyMaterial {
    Initial {
        profile: NewUser,
        encrypted_private_key: Vec<u8>,
    },
    Rotate {
        public_key_pem: String,
        encrypted_private_key: Vec<u8>,
    },
}

/// 密钥申请的审批输入。审批时间由存储层记录。
///
/// 该类型间接携带私钥密文，因此故意不实现 `Debug` 或序列化。
pub struct KeyRequestApproval {
    pub request_id: String,
    pub reviewer_account_id: String,
    pub expires_at: i64,
    pub material: ApprovedKeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRequestApprovalResult {
    pub request: KeyGenerationRequest,
    pub managed_user: ManagedUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessProtocol {
    Tcp,
    Udp,
}

impl AccessProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccessRecord {
    pub username: String,
    pub protocol: AccessProtocol,
    pub target_host: String,
    pub target_port: u16,
    pub accessed_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRecord {
    pub record_id: i64,
    pub username: String,
    pub protocol: AccessProtocol,
    pub target_host: String,
    pub target_port: u16,
    pub access_count: u64,
    pub accessed_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessLogSettings {
    pub retention_days: u16,
}

impl Default for AccessLogSettings {
    fn default() -> Self {
        Self {
            retention_days: DEFAULT_ACCESS_LOG_RETENTION_DAYS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapOutcome {
    Created(WebAccount),
    AlreadyExists,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportOutcome {
    SourceMissing,
    AlreadyHandled,
    Imported { users: usize },
    SkippedNonEmptyDatabase { users: usize },
}
