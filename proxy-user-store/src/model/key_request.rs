use serde::{Deserialize, Serialize};

use super::{ManagedUser, NewUser};

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

/// 用户或管理员账号的密钥生成或轮换申请。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyGenerationRequest {
    pub request_id: String,
    pub account_id: String,
    pub request_message: Option<String>,
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
    pub request_message: Option<String>,
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
