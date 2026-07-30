use serde::{Deserialize, Serialize};

use super::{NewUser, ProxyAddress, UserRecord};

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
    pub assigned_proxy_addresses: Vec<ProxyAddress>,
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
    pub proxy_address_ids: Option<Vec<String>>,
    /// 执行账号停用的管理员快照。存储实现应在 active -> disabled 时写入审计记录。
    pub disabled_by: Option<AccountActor>,
    /// 修改登录状态、Proxy 连接状态或权限的管理员快照。
    pub changed_by: Option<AccountActor>,
    /// 管理员执行受审计变更时填写的原因。
    pub audit_reason: Option<String>,
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
            && self.proxy_address_ids.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountActor {
    pub account_id: String,
    pub login_name: String,
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
    pub proxy_address_ids: Vec<String>,
    /// 管理端创建用户时的操作者；内部迁移和测试可不提供。
    pub created_by: Option<AccountActor>,
    pub audit_reason: Option<String>,
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
    /// 发起本次密钥重生成的用户本人或管理员。
    pub actor: AccountActor,
    /// 管理员重生成密钥时填写的原因；用户本人自助操作可为空。
    pub audit_reason: Option<String>,
}
