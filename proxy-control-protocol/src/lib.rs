//! Proxy Entry 与 Proxy Registry 之间的版本化控制面协议。
//!
//! 这个 crate 只包含不依赖存储实现的 DTO 和协议常量。Entry 不应通过它
//! 获得任何账号密码、私钥信封或 Agent 访问令牌。

use serde::{Deserialize, Serialize};

pub const CONTROL_PROTOCOL_VERSION: u16 = 3;
pub const CONTROL_HEALTH_PATH: &str = "/control/v1/health";
pub const ENTRY_REGISTRATION_PATH: &str = "/control/v1/entries/register";
pub const AUTHORIZATION_RESOLVE_PATH: &str = "/control/v1/authorizations/resolve";
pub const AUTHORIZATION_EVENTS_PATH: &str = "/control/v1/events";
pub const ACCESS_BATCHES_PATH: &str = "/control/v1/access-batches";

pub const MAX_ENTRY_ID_BYTES: usize = 128;
pub const MAX_ENTRY_VERSION_BYTES: usize = 64;
pub const MAX_ADVERTISED_ADDRESS_BYTES: usize = 512;
pub const MAX_BATCH_ID_BYTES: usize = 128;
pub const MAX_ACCESS_EVENTS_PER_BATCH: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlHealthResponse {
    pub status: String,
    pub protocol_version: u16,
    pub registry_instance_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryRegistrationRequest {
    pub entry_id: String,
    pub version: String,
    pub protocol_version: u16,
    pub advertised_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryRegistrationResponse {
    pub registry_instance_id: String,
    pub protocol_version: u16,
    pub received_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationResolveRequest {
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationResolveResponse {
    pub authorization: Option<AuthorizationSnapshot>,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationSnapshot {
    pub username: String,
    pub public_key_pem: String,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub key_version: i64,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationEvent {
    pub revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessEvent {
    pub username: String,
    pub protocol: AccessProtocol,
    pub target_host: String,
    pub target_port: u16,
    pub accessed_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessBatchRequest {
    pub entry_id: String,
    pub batch_id: String,
    pub events: Vec<AccessEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessBatchResponse {
    pub accepted: bool,
}
