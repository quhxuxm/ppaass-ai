use crate::{
    AccessLogRepository, AccessLogSettings, AccessProtocol, AccessRecord,
    DEFAULT_ACCESS_LOG_RETENTION_DAYS, MAX_ACCESS_LOG_QUERY_LIMIT, MAX_ACCESS_LOG_RETENTION_DAYS,
    MIN_ACCESS_LOG_RETENTION_DAYS, NewAccessRecord, Result, SqliteFilePermissions,
    UserRepositoryError, ValidationError, normalize_username,
};
use async_trait::async_trait;
use sqlx::{
    Connection, Row, SqlitePool,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
    },
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{info, instrument};

const ACCESS_LOG_SCHEMA_VERSION: i64 = 1;
const ACCESS_LOG_RETENTION_DAYS_KEY: &str = "access_log_retention_days";
const LEGACY_USER_DATABASE_IMPORT_KEY: &str = "legacy_user_database_access_import_v1";
const LEGACY_USER_DATABASE_CLEANUP_KEY: &str = "access_log_split_cleanup_v1";
const LEGACY_USER_DATABASE_CHECKPOINT_KEY: &str = "access_log_split_checkpoint_v1";
const MAX_ACCESS_TARGET_HOST_BYTES: usize = 1_024;
const ACCESS_RECORD_SELECT: &str = "record_id, username, protocol, target_host, target_port, \
                                    access_count, accessed_at";

/// SQLite adapter dedicated to proxy access history.
///
/// It deliberately has no account or key-management implementation. Deployments can therefore
/// grant the Proxy process write access to this database without granting write access to the
/// user/account database.
#[derive(Debug, Clone)]
pub struct SqliteAccessLogRepository {
    pool: SqlitePool,
    path: PathBuf,
    file_permissions: SqliteFilePermissions,
}

mod checkpoint;
mod connection;
mod helpers;
mod legacy;
mod repository;

use helpers::*;

#[cfg(test)]
mod tests;
