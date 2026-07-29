use serde::{Deserialize, Serialize};

use super::WebAccount;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDeviceAuthorizationStatus {
    Pending,
    Authorized,
    Denied,
    Consumed,
}

impl AgentDeviceAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Authorized => "authorized",
            Self::Denied => "denied",
            Self::Consumed => "consumed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "authorized" => Some(Self::Authorized),
            "denied" => Some(Self::Denied),
            "consumed" => Some(Self::Consumed),
            _ => None,
        }
    }
}

/// Agent 浏览器登录使用的短期授权记录。
///
/// 两个 code 字段都只保存带域分隔的 SHA-256 摘要，不保存设备码或用户短码明文。
#[derive(Clone, PartialEq, Eq)]
pub struct AgentDeviceAuthorization {
    pub device_code_hash: String,
    pub user_code_hash: String,
    pub client_name: String,
    pub platform: String,
    pub status: AgentDeviceAuthorizationStatus,
    pub authorized_account_id: Option<String>,
    pub authorized_auth_version: Option<i64>,
    pub created_at: i64,
    pub expires_at: i64,
    pub authorized_at: Option<i64>,
    pub consumed_at: Option<i64>,
    pub last_polled_at: Option<i64>,
}

/// 创建 Agent 设备授权 challenge 的数据库无关输入。
///
/// 调用方负责生成高熵 code，并仅将摘要传给存储层。
pub struct NewAgentDeviceAuthorization {
    pub device_code_hash: String,
    pub user_code_hash: String,
    pub client_name: String,
    pub platform: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentDeviceAuthorizationDecision {
    Authorized,
    Denied,
    AlreadyAuthorized,
    AlreadyDenied,
    Expired,
    Finalized,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDeviceAuthorizationPoll {
    NotFound,
    Expired,
    Pending {
        retry_after_seconds: u32,
    },
    SlowDown {
        retry_after_seconds: u32,
    },
    Denied,
    Consumed,
    Authorized {
        account_id: String,
        account_auth_version: i64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentDeviceAuthorizationFinalize {
    Finalized,
    AlreadyFinalized,
    Expired,
    Invalidated,
    NotFound,
}

/// Agent 领取凭据前由业务层读取并验证的账号/Profile 快照。
///
/// 存储层在最终 CAS 时必须再次核对这些字段，避免审批后并发停用、改权或
/// 轮换密钥时返回过期凭据。
pub struct AgentDeviceAuthorizationClaim {
    pub device_code_hash: String,
    pub account_id: String,
    pub account_auth_version: i64,
    pub username: String,
    pub permissions: Vec<String>,
    pub key_version: i64,
    pub expires_at: Option<i64>,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapOutcome {
    Created(WebAccount),
    AlreadyExists,
}
