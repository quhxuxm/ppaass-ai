//! Proxy 与管理 Web 服务共用的用户模型、校验和 SQLite 存储。

mod access_sqlite;
mod model;
mod repository;
mod sqlite;
mod validation;

pub use access_sqlite::SqliteAccessLogRepository;
pub use model::{
    AGENT_EGRESS_EDIT_PERMISSION, AGENT_PACKET_CAPTURE_PERMISSION,
    AGENT_RUNTIME_THREADS_EDIT_PERMISSION, AccessLogSettings, AccessProtocol, AccessRecord,
    AccountActor, AccountRole, AccountStatus, AgentDeviceAuthorization,
    AgentDeviceAuthorizationClaim, AgentDeviceAuthorizationDecision,
    AgentDeviceAuthorizationFinalize, AgentDeviceAuthorizationPoll, AgentDeviceAuthorizationStatus,
    AgentEventRecord, AgentWebSessionHandoffConsume, AgentWebSessionHandoffCreate,
    ApprovedKeyMaterial, AuditAction, AuditEvent, AuditEventQuery, AuditTargetKind,
    BootstrapOutcome, DEFAULT_ACCESS_LOG_RETENTION_DAYS, DEPRECATED_AGENT_CONFIG_VIEW_PERMISSION,
    EncryptedPrivateKey, ExternalIdentity, KEY_ROTATE_PERMISSION, KeyEncryptionBinding,
    KeyGenerationRequest, KeyPairRotation, KeyRequestApproval, KeyRequestApprovalResult,
    KeyRequestKind, KeyRequestRejection, KeyRequestStatus, LoginRecord, MAX_ACCESS_LOG_QUERY_LIMIT,
    MAX_ACCESS_LOG_RETENTION_DAYS, MIN_ACCESS_LOG_RETENTION_DAYS, ManagedUser, ManagedUserUpdate,
    NewAccessRecord, NewAdminAccount, NewAgentDeviceAuthorization, NewAgentWebSessionHandoff,
    NewKeyGenerationRequest, NewManagedUser, NewProxyAddress, NewUser, NewUserAccount,
    PRIVATE_KEY_READ_PERMISSION, PROXY_CONNECT_TCP_PERMISSION, PROXY_CONNECT_UDP_PERMISSION,
    ProxyAddress, ProxyAddressUpdate, UserOrigin, UserRecord, UserUpdate, WebAccount,
    default_proxy_permissions,
};
pub use repository::{
    AccessLogRepository, AccountRepository, AgentDeviceAuthorizationRepository,
    AgentEventRepository, AgentWebSessionHandoffRepository, AuditLogRepository,
    ProxyAddressRepository, UserRepository,
};
pub use sqlite::{SqliteFilePermissions, SqliteUserRepository};
pub use validation::{
    MAX_AUDIT_REASON_CHARS, MAX_KEY_REQUEST_MESSAGE_CHARS, MAX_KEY_REQUEST_REJECTION_REASON_CHARS,
    MAX_PERMISSION_CODE_BYTES, MAX_PERMISSIONS, MAX_PROXY_ADDRESS_BYTES,
    MAX_PROXY_ADDRESS_LABEL_BYTES, MAX_PROXY_ADDRESSES_PER_ACCOUNT, MAX_PUBLIC_KEY_PEM_BYTES,
    MAX_USERNAME_BYTES, ValidationError, normalize_audit_reason, normalize_key_request_message,
    normalize_key_request_rejection_reason, normalize_permissions, normalize_proxy_address,
    normalize_proxy_address_id, normalize_proxy_address_ids, normalize_proxy_address_label,
    normalize_public_key_pem, normalize_username, parse_expires_at, validate_user,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum UserRepositoryError {
    #[error("用户数据校验失败：{0}")]
    Validation(#[from] ValidationError),

    #[error("用户存储操作失败：{source}")]
    Storage {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("读取用户配置失败：{0}")]
    Io(#[from] std::io::Error),

    #[error("用户已存在：{0}")]
    Conflict(String),

    #[error("用户不存在：{0}")]
    NotFound(String),

    #[error("数据库布局或迁移配置无效：{0}")]
    InvalidDatabaseLayout(String),

    #[error("用户数据库 schema 不兼容：{0}")]
    InvalidSchema(String),

    #[error("账号必须先停用才能删除：{0}")]
    AccountMustBeDisabled(String),

    #[error("根管理员 admin 不能被停用、降级或删除")]
    RootAdminProtected,

    #[error("用户 {username} 的密钥版本冲突：期望 {expected}，实际 {actual}")]
    VersionConflict {
        username: String,
        expected: i64,
        actual: i64,
    },

    #[error("账号 {account_id} 的认证版本冲突：期望 {expected}，实际 {actual}")]
    AccountVersionConflict {
        account_id: String,
        expected: i64,
        actual: i64,
    },

    #[error("外部身份已被占用：{provider}/{subject}")]
    ExternalIdentityConflict { provider: String, subject: String },

    #[error("账号 {account_id} 已有待审批密钥申请：{request_id}")]
    PendingKeyRequestConflict {
        account_id: String,
        request_id: String,
    },

    #[error("密钥申请不存在：{0}")]
    KeyRequestNotFound(String),

    #[error("密钥申请 {request_id} 已被处理，当前状态为 {status:?}")]
    KeyRequestAlreadyReviewed {
        request_id: String,
        status: KeyRequestStatus,
    },

    #[error("账号 {account_id} 当前不能申请密钥：{reason}")]
    KeyRequestNotEligible { account_id: String, reason: String },

    #[error("审批过期时间 {expires_at} 必须晚于当前时间 {now}")]
    InvalidApprovalExpiration { expires_at: i64, now: i64 },

    #[error("密钥申请 {request_id} 已失效：{reason}")]
    StaleKeyRequest { request_id: String, reason: String },

    #[error("审批账号不是启用的管理员：{account_id}")]
    ReviewerNotActiveAdmin { account_id: String },

    #[error("Agent 设备授权 challenge 冲突")]
    AgentDeviceAuthorizationConflict,

    #[error("Agent 设备授权 challenge 数量已达到安全上限")]
    AgentDeviceAuthorizationCapacity,

    #[error("普通用户账号数量已达到安全上限")]
    UserAccountCapacity,

    #[error("Proxy 地址目录容量已满")]
    ProxyAddressCapacity,

    #[error("Proxy 地址不存在：{0}")]
    ProxyAddressNotFound(String),

    #[error("Proxy 地址已存在：{0}")]
    ProxyAddressConflict(String),

    #[error("Proxy 地址仍被账号分配，必须先重新分配：{0}")]
    ProxyAddressInUse(String),

    #[error("Proxy 地址已停用，不能分配：{0}")]
    ProxyAddressDisabled(String),

    #[error("Proxy 地址必须先停用才能删除：{0}")]
    ProxyAddressMustBeDisabled(String),

    #[error("账号没有分配可用的 Proxy 地址：{0}")]
    ProxyAddressNotAssigned(String),
}

pub type Result<T> = std::result::Result<T, UserRepositoryError>;

impl From<sqlx::Error> for UserRepositoryError {
    fn from(source: sqlx::Error) -> Self {
        Self::Storage {
            source: Box::new(source),
        }
    }
}
