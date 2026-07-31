//! PPAASS Proxy 用户管理 Web 服务。

mod agent_events;
mod agent_tokens;
mod api;
mod auth;
mod control_api;
mod error;
mod rate_limit;
mod secrets;
pub mod store;
mod web_handoffs;

pub use store::*;

pub use agent_events::AgentEventHub;
pub use agent_tokens::{AgentAccessTokenError, AgentAccessTokenService};
pub use api::{AppState, build_router};
pub use auth::{PasswordError, PasswordService, SessionStore};
pub use control_api::{ControlState, ControlTokenVerifier, build_control_router};
pub use rate_limit::AgentDeviceAuthorizationGuard;
pub use secrets::{PrivateKeyCipher, PrivateKeyCipherError};
pub use web_handoffs::AgentWebSessionHandoffStore;
