use super::model::NewAuditEvent;
use crate::{
    AccessLogRepository, AccessLogSettings, AccessProtocol, AccessRecord, AccountActor,
    AccountRepository, AccountRole, AccountStatus, AgentDeviceAuthorization,
    AgentDeviceAuthorizationClaim, AgentDeviceAuthorizationDecision,
    AgentDeviceAuthorizationFinalize, AgentDeviceAuthorizationPoll,
    AgentDeviceAuthorizationRepository, AgentDeviceAuthorizationStatus,
    AgentWebSessionHandoffConsume, AgentWebSessionHandoffCreate, AgentWebSessionHandoffRepository,
    ApprovedKeyMaterial, AuditAction, AuditEvent, AuditEventQuery, AuditLogRepository,
    AuditTargetKind, BootstrapOutcome, DEFAULT_ACCESS_LOG_RETENTION_DAYS,
    DEPRECATED_AGENT_CONFIG_VIEW_PERMISSION, EncryptedPrivateKey, ExternalIdentity,
    KeyEncryptionBinding, KeyGenerationRequest, KeyPairRotation, KeyRequestApproval,
    KeyRequestApprovalResult, KeyRequestKind, KeyRequestRejection, KeyRequestStatus, LoginRecord,
    MAX_ACCESS_LOG_QUERY_LIMIT, MAX_ACCESS_LOG_RETENTION_DAYS, MIN_ACCESS_LOG_RETENTION_DAYS,
    ManagedUser, ManagedUserUpdate, NewAccessRecord, NewAdminAccount, NewAgentDeviceAuthorization,
    NewAgentWebSessionHandoff, NewKeyGenerationRequest, NewManagedUser, NewProxyAddress, NewUser,
    NewUserAccount, ProxyAddress, ProxyAddressRepository, ProxyAddressUpdate, Result, UserOrigin,
    UserRecord, UserRepository, UserRepositoryError, UserUpdate, ValidationError, WebAccount,
    normalize_audit_reason, normalize_key_request_message, normalize_key_request_rejection_reason,
    normalize_permissions, normalize_proxy_address, normalize_proxy_address_id,
    normalize_proxy_address_ids, normalize_proxy_address_label, normalize_public_key_pem,
    normalize_username, validate_user,
};
use async_trait::async_trait;
use sqlx::{
    QueryBuilder, Row, Sqlite, SqliteConnection, SqlitePool, Transaction,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
    },
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{info, instrument, warn};

const ACCESS_LOG_RETENTION_DAYS_KEY: &str = "access_log_retention_days";
// Persisted metadata key retained across the Proxy Registry rename.
const KEY_ENCRYPTION_VERIFIER_KEY: &str = "proxy_web_key_encryption_verifier_v1";
const SQLITE_SCHEMA_VERSION: i64 = 12;
const MAX_ACCOUNT_ID_BYTES: usize = 128;
const MAX_PROVIDER_BYTES: usize = 64;
const MAX_PROVIDER_SUBJECT_BYTES: usize = 512;
const MAX_PASSWORD_HASH_BYTES: usize = 4096;
const MAX_DISPLAY_NAME_BYTES: usize = 256;
const MAX_EMAIL_BYTES: usize = 320;
const MAX_AVATAR_URL_BYTES: usize = 1_500_000;
const MAX_PRIVATE_KEY_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_ACCESS_TARGET_HOST_BYTES: usize = 1_024;
const DEVICE_CODE_HASH_BYTES: usize = 43;
const USER_CODE_HASH_BYTES: usize = 43;
const MAX_AGENT_CLIENT_NAME_BYTES: usize = 128;
const MAX_AGENT_PLATFORM_BYTES: usize = 32;
const MAX_ACTIVE_DEVICE_AUTHORIZATIONS: i64 = 10_000;
const MAX_USER_ACCOUNTS: i64 = 100_000;
const MAX_PROXY_ADDRESS_CATALOG_SIZE: i64 = 10_000;
const DEVICE_AUTHORIZATION_HISTORY_SECONDS: i64 = 86_400;
const DEVICE_AUTHORIZATION_MAINTENANCE_SECONDS: i64 = 30;
// These two legacy demo keypairs were committed to the public repository. Matching legacy
// profiles are disabled on every writable Web startup so an already-imported production
// database cannot silently keep accepting the compromised private keys. A legitimate user can
// recover only by rotating to a different key through the normal admin workflow.
const COMPROMISED_BUNDLED_DEMO_PUBLIC_KEYS: [&str; 2] = [
    r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtm6UwXI/ZmUrWPF9gkXs
vmnh/77vci16aGJBZv9BM7+wuY2ml7mvdYFbGVPiKB9LC4tudvGmv298XuecKxuz
HRoSwspj2qnr8wA1qsjHlVKaACVKKSgajlRE4bkBxylyfIZmXGOQrrzvuu61Ku3S
xAPMzdW5EUIaHHJ5bd01ZfEJ6vsJKLG8cT9Iyj+ssED8pRTRp2jbtVJ/sNqc0tS1
MznDGEVOa8UzyZUa8aGaQjGQExAzRCCDzh3ceSedIhp4ySs6Kud7nsQSgFVc0pxc
PxzO8/ImXr5KWigaTnkfTVGFzFHrzgTdqPJiLtNRPCmxQAMZpu/U9nxCA5YY2xR5
ywIDAQAB
-----END PUBLIC KEY-----"#,
    r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0yqkQjUeFaYbsJxiUJtW
s3Jd22uAg7fyGyZZAtzI6JNmF/L8zeHxoWhUjEOUuwHmRn4AaEvgSbjFIwnPuVGm
qCAd8h31379p3Mp5ahA4IMDarb6PUoKDDIxSAYUfkRtpjNZilPVeh2eFWyH41NrS
NyuKhxQ/aMnVoDrwuEwJQM5K8hdo0pwnfQv3yNtX16E3woe/vTb5f2fvPMZfz0sQ
rqKBednzxoJ3Zd5SCHBBTnD4u6VVzKlkQc9qpsSIkhJ8jQK4SsxCXlKH2vrsYAHj
Xsg2dea7zeV8pRw0uL010Cx208clFEtV3EMdgY2iSpbTW+gOuhgciVdzjR/EAXtH
lwIDAQAB
-----END PUBLIC KEY-----"#,
];

/// Unix file permissions applied to the SQLite database and its sidecar files.
///
/// `OwnerAndGroup` only adds group read/write bits. It intentionally does not
/// change ownership: deployments using separate service users must place the
/// database in a trusted setgid directory owned by their shared group. On
/// non-Unix platforms this policy is accepted but file access remains governed
/// by the platform's native ACLs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SqliteFilePermissions {
    /// Restrict the database, WAL, SHM and rollback journal to the owner (`0600`).
    #[default]
    OwnerOnly,
    /// Permit the owner to write and the inherited group to read (`0640`).
    OwnerReadWriteGroupRead,
    /// Permit both the owner and the inherited group to access the files (`0660`).
    OwnerAndGroup,
}

#[cfg(unix)]
impl SqliteFilePermissions {
    pub(crate) const fn unix_mode(self) -> u32 {
        match self {
            Self::OwnerOnly => 0o600,
            Self::OwnerReadWriteGroupRead => 0o640,
            Self::OwnerAndGroup => 0o660,
        }
    }
}

const USER_SELECT: &str = "username, public_key_pem, permissions, enabled, origin, \
                           key_version, expires_at, created_at, updated_at";
const ACCOUNT_SELECT: &str = "account_id, login_name, role, status, linked_username, \
                              display_name, email, avatar_url, auth_version, last_login_at, \
                              created_at, updated_at";
const QUALIFIED_ACCOUNT_SELECT: &str = "a.account_id, a.login_name, a.role, a.status, \
                                        a.linked_username, a.display_name, a.email, a.avatar_url, \
                                        a.auth_version, a.last_login_at, a.created_at, a.updated_at";
const KEY_REQUEST_SELECT: &str = "request_id, account_id, kind, status, expected_key_version, \
                                  reviewer_account_id, reviewer_login_name, rejection_reason, \
                                  requested_at, reviewed_at, approved_expires_at, request_message";
const ACCESS_RECORD_SELECT: &str = "record_id, username, protocol, target_host, target_port, \
                                    access_count, accessed_at";
const DEVICE_AUTHORIZATION_SELECT: &str = "device_code_hash, user_code_hash, client_name, \
                                           platform, status, authorized_account_id, \
                                           authorized_auth_version, created_at, expires_at, \
                                           authorized_at, consumed_at, last_polled_at";

#[derive(Debug, Clone)]
pub struct SqliteUserRepository {
    pool: SqlitePool,
    path: PathBuf,
    file_permissions: SqliteFilePermissions,
    max_user_accounts: i64,
    device_authorization_maintenance: Arc<Mutex<DeviceAuthorizationMaintenance>>,
}

#[derive(Debug)]
struct DeviceAuthorizationMaintenance {
    active_count: i64,
    next_run_at: i64,
}

mod access_repository;
mod account;
mod agent_events;
mod agent_web_session_handoffs;
mod audit_logs;
mod connection;
mod database_queries;
mod device;
mod file_permissions;
mod migration_access;
mod migration_account_audits;
mod migration_agent_events;
mod migration_audits;
mod migration_device;
mod migration_key_requests;
mod migration_permissions;
mod migration_proxy_addresses;
mod migration_users;
mod migration_validation;
mod normalization;
mod proxy_addresses;
mod rows;
mod user_repository;

use agent_events::*;
use audit_logs::*;
use database_queries::*;
#[cfg(unix)]
use file_permissions::*;
use migration_access::*;
use migration_account_audits::*;
use migration_agent_events::*;
use migration_audits::*;
use migration_device::*;
use migration_key_requests::*;
use migration_permissions::*;
use migration_proxy_addresses::*;
use migration_users::*;
use migration_validation::*;
use normalization::*;
use proxy_addresses::*;
use rows::*;

#[cfg(test)]
mod tests;
