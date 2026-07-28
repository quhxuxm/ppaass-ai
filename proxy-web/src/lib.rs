//! PPAASS Proxy 用户管理 Web 服务。

mod api;
mod auth;
mod error;
mod rate_limit;
mod secrets;

pub use api::{AppState, build_router};
pub use auth::{PasswordError, PasswordService, SessionStore};
pub use rate_limit::AgentDeviceAuthorizationGuard;
pub use secrets::{PrivateKeyCipher, PrivateKeyCipherError};
