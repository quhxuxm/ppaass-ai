//! PPAASS Proxy 用户管理 Web 服务。

mod agent_events;
mod agent_tokens;
mod api;
mod auth;
mod control_api;
mod error;
mod secrets;
mod startup;
pub mod store;
mod web_handoffs;

pub use store::*;

pub use agent_events::{AgentEventHub, AgentServerEvent};
pub use agent_tokens::{
    AGENT_ACCESS_TOKEN_TTL_SECONDS, AGENT_PROFILE_REFRESH_SECONDS, AgentAccessTokenClaims,
    AgentAccessTokenError, AgentAccessTokenService,
};
pub use api::{
    AppState, agent_default_permissions, build_router, build_router_with_timeout,
    hash_agent_user_code, include_required_agent_permissions, request_path_for_trace,
    resolve_assigned_proxy_addresses,
};
pub use auth::{PasswordError, PasswordService, SessionStore, session_token, validate_password};
pub use control_api::{ControlState, ControlTokenVerifier, build_control_router};
pub use error::ApiError;
pub use secrets::{PrivateKeyCipher, PrivateKeyCipherError};
pub use startup::{
    bool_env, bootstrap_admin, ensure_key_encryption_binding, init_tracing, registry_instance_id,
    select_database_file_permissions, validate_listen_address,
};
pub use web_handoffs::{
    AGENT_WEB_SESSION_HANDOFF_TTL_SECONDS, AgentWebSessionHandoffConsumeError,
    AgentWebSessionHandoffIssueError, AgentWebSessionHandoffStore,
};
