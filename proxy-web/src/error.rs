use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use proxy_user_store::UserRepositoryError;
use serde::Serialize;
use tracing::error;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
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
        }
    }

    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "请先登录".to_string(),
        }
    }

    pub fn invalid_credentials() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_credentials",
            message: "用户名或密码错误".to_string(),
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: message.into(),
        }
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    pub fn method_not_allowed() -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: "method_not_allowed",
            message: "该 API 不支持此 HTTP 方法".to_string(),
        }
    }

    pub fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            code: "oauth_upstream_error",
            message: message.into(),
        }
    }

    pub fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "服务器内部错误".to_string(),
        }
    }

    pub fn is_unauthorized(&self) -> bool {
        self.status == StatusCode::UNAUTHORIZED
    }

    pub fn from_json_rejection(rejection: JsonRejection) -> Self {
        let status = rejection.status();
        tracing::debug!(reason = %rejection.body_text(), "拒绝无效 JSON 请求");
        Self {
            status,
            code: if status == StatusCode::PAYLOAD_TOO_LARGE {
                "payload_too_large"
            } else {
                "invalid_json"
            },
            message: if status == StatusCode::PAYLOAD_TOO_LARGE {
                "请求体不能超过 20 KiB".to_string()
            } else {
                "JSON 请求格式或 Content-Type 无效".to_string()
            },
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
            },
            UserRepositoryError::NotFound(username) => Self {
                status: StatusCode::NOT_FOUND,
                code: "user_not_found",
                message: format!("用户 {username} 不存在"),
            },
            UserRepositoryError::LastAdmin => {
                Self::conflict("last_admin", "不能停用、降级或删除最后一个启用的管理员")
            }
            UserRepositoryError::VersionConflict {
                username,
                expected,
                actual,
            } => Self::conflict(
                "version_conflict",
                format!("用户 {username} 的密钥版本已变化（期望 {expected}，实际 {actual}）"),
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
        response
    }
}
