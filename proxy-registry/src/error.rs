use crate::store::UserRepositoryError;
use axum::{
    Json,
    extract::rejection::{BytesRejection, JsonRejection, QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::error;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    retry_after_seconds: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "请先登录".to_string(),
            retry_after_seconds: None,
        }
    }

    pub fn invalid_credentials() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_credentials",
            message: "用户名或密码错误".to_string(),
            retry_after_seconds: None,
        }
    }

    pub fn invalid_current_password() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "current_password_invalid",
            message: "当前密码不正确".to_string(),
            retry_after_seconds: None,
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    pub fn method_not_allowed() -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: "method_not_allowed",
            message: "该 API 不支持此 HTTP 方法".to_string(),
            retry_after_seconds: None,
        }
    }

    pub fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "服务器内部错误".to_string(),
            retry_after_seconds: None,
        }
    }

    pub fn device_authorization_error(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        retry_after_seconds: Option<u32>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after_seconds,
        }
    }

    pub fn is_unauthorized(&self) -> bool {
        self.status == StatusCode::UNAUTHORIZED
    }

    pub fn from_json_rejection(rejection: JsonRejection) -> Self {
        let status = rejection.status();
        tracing::debug!(
            status = status.as_u16(),
            "拒绝无效 JSON 请求；不记录解析错误文本以免回显请求值"
        );
        Self {
            status,
            code: if status == StatusCode::PAYLOAD_TOO_LARGE {
                "payload_too_large"
            } else {
                "invalid_json"
            },
            message: if status == StatusCode::PAYLOAD_TOO_LARGE {
                "请求体不能超过 32 KiB".to_string()
            } else {
                "JSON 请求格式或 Content-Type 无效".to_string()
            },
            retry_after_seconds: None,
        }
    }

    pub fn from_bytes_rejection(rejection: BytesRejection) -> Self {
        let status = rejection.status();
        tracing::debug!(reason = %rejection.body_text(), "拒绝无法读取的请求体");
        Self {
            status,
            code: if status == StatusCode::PAYLOAD_TOO_LARGE {
                "payload_too_large"
            } else {
                "invalid_request"
            },
            message: if status == StatusCode::PAYLOAD_TOO_LARGE {
                "请求体不能超过 32 KiB".to_string()
            } else {
                "无法读取请求体".to_string()
            },
            retry_after_seconds: None,
        }
    }

    pub fn from_query_rejection(rejection: QueryRejection) -> Self {
        let status = rejection.status();
        tracing::debug!(
            status = status.as_u16(),
            "拒绝无效查询参数；不记录解析错误文本以免泄露一次性交接码"
        );
        Self {
            status,
            code: "invalid_request",
            message: "查询参数格式无效".to_string(),
            retry_after_seconds: None,
        }
    }
}

impl From<UserRepositoryError> for ApiError {
    fn from(error: UserRepositoryError) -> Self {
        match error {
            UserRepositoryError::Validation(error) => Self::bad_request(error.to_string()),
            UserRepositoryError::Conflict(username) => Self {
                status: StatusCode::CONFLICT,
                code: "user_exists",
                message: format!("用户 {username} 已存在"),
                retry_after_seconds: None,
            },
            UserRepositoryError::NotFound(username) => Self {
                status: StatusCode::NOT_FOUND,
                code: "user_not_found",
                message: format!("用户 {username} 不存在"),
                retry_after_seconds: None,
            },
            UserRepositoryError::AccountMustBeDisabled(_) => {
                Self::conflict("account_not_disabled", "只有已停用的账号才能删除")
            }
            UserRepositoryError::RootAdminProtected => Self::conflict(
                "root_admin_protected",
                "根管理员 admin 不能被停用、降级或删除",
            ),
            UserRepositoryError::VersionConflict {
                username,
                expected,
                actual,
            } => Self::conflict(
                "version_conflict",
                format!("用户 {username} 的密钥版本已变化（期望 {expected}，实际 {actual}）"),
            ),
            UserRepositoryError::AccountVersionConflict { .. } => Self::conflict(
                "account_version_conflict",
                "账号认证信息已经变化，请重新登录后再试",
            ),
            UserRepositoryError::ExternalIdentityConflict { .. } => {
                Self::conflict("external_identity_conflict", "该第三方账号已绑定其他用户")
            }
            UserRepositoryError::PendingKeyRequestConflict { .. } => {
                Self::conflict("key_request_pending", "该账号已有待审批密钥申请")
            }
            UserRepositoryError::KeyRequestNotFound(_) => Self::not_found("密钥申请不存在"),
            UserRepositoryError::KeyRequestAlreadyReviewed { .. } => {
                Self::conflict("key_request_already_reviewed", "密钥申请已被处理")
            }
            UserRepositoryError::KeyRequestNotEligible { reason, .. } => {
                Self::conflict("key_request_not_eligible", reason)
            }
            UserRepositoryError::InvalidApprovalExpiration { .. } => {
                Self::bad_request("审批有效期必须严格晚于当前时间")
            }
            UserRepositoryError::StaleKeyRequest { reason, .. } => {
                Self::conflict("stale_key_request", reason)
            }
            UserRepositoryError::ReviewerNotActiveAdmin { .. } => {
                Self::forbidden("审批人不是启用的管理员")
            }
            UserRepositoryError::AgentDeviceAuthorizationCapacity => {
                Self::device_authorization_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "device_authorization_capacity",
                    "当前设备授权请求过多，请稍后重试",
                    Some(30),
                )
            }
            UserRepositoryError::UserAccountCapacity => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "registration_capacity",
                message: "当前账号容量已满，请联系管理员".to_string(),
                retry_after_seconds: None,
            },
            UserRepositoryError::ProxyAddressCapacity => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "proxy_address_capacity",
                message: "Proxy 地址目录容量已满".to_string(),
                retry_after_seconds: None,
            },
            UserRepositoryError::ProxyAddressNotFound(_) => Self::not_found("Proxy 地址不存在"),
            UserRepositoryError::ProxyAddressConflict(_) => {
                Self::conflict("proxy_address_exists", "Proxy 地址或 ID 已存在")
            }
            UserRepositoryError::ProxyAddressInUse(_) => Self::conflict(
                "proxy_address_in_use",
                "该 Proxy 地址仍被账号分配，请先重新分配相关账号",
            ),
            UserRepositoryError::ProxyAddressDisabled(_) => {
                Self::conflict("proxy_address_disabled", "不能分配已停用的 Proxy 地址")
            }
            UserRepositoryError::ProxyAddressNotAssigned(_) => Self::conflict(
                "proxy_address_not_assigned",
                "账号尚未分配可用的 Proxy 地址，请联系管理员",
            ),
            UserRepositoryError::AgentDeviceAuthorizationConflict => Self::internal(),
            error => {
                error!(error = %error, "用户管理 API 数据库操作失败");
                Self::internal()
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: ErrorDetail {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Session"),
            );
        }
        if let Some(retry_after_seconds) = self.retry_after_seconds
            && let Ok(value) = axum::http::HeaderValue::from_str(&retry_after_seconds.to_string())
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
        response
    }
}
