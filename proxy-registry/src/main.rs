use anyhow::{Context, Result, bail};
use clap::Parser;
use proxy_registry::{
    AccessBatchRepository, AccessLogRepository, AgentAccessTokenService,
    AgentDeviceAuthorizationGuard, AgentWebSessionHandoffStore, AppState, ControlState,
    ControlTokenVerifier, PasswordService, PrivateKeyCipher, ProxyEntryRepository, SessionStore,
    SqliteAccessLogRepository, SqliteFilePermissions, SqliteUserRepository, UserRepository,
    bool_env, bootstrap_admin, build_control_router, build_router, ensure_key_encryption_binding,
    init_tracing, registry_instance_id, select_database_file_permissions, validate_listen_address,
};
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use time::OffsetDateTime;
use tracing::{info, warn};

#[path = "main/runtime.rs"]
mod runtime;
use runtime::serve_public_and_control;

const KEY_ENCRYPTION_SECRET_ENV: &str = "PPAASS_PROXY_REGISTRY_KEY_ENCRYPTION_SECRET";
const ALLOW_REGISTRATION_ENV: &str = "PPAASS_PROXY_REGISTRY_ALLOW_REGISTRATION";
const SECURE_COOKIES_ENV: &str = "PPAASS_PROXY_REGISTRY_SECURE_COOKIES";
const TRUST_PROXY_HEADERS_ENV: &str = "PPAASS_PROXY_REGISTRY_TRUST_PROXY_HEADERS";
const DATABASE_GROUP_READABLE_ENV: &str = "PPAASS_PROXY_REGISTRY_DATABASE_GROUP_READABLE";
const ACCESS_LOG_DATABASE_GROUP_WRITABLE_ENV: &str =
    "PPAASS_PROXY_REGISTRY_ACCESS_LOG_DATABASE_GROUP_WRITABLE";
const CONTROL_TOKEN_ENV: &str = "PPAASS_PROXY_REGISTRY_CONTROL_TOKEN";
const SECONDS_PER_DAY: i64 = 24 * 60 * 60;
#[derive(Debug, Parser)]
#[command(author, version, about = "PPAASS Proxy 用户管理 Web 服务")]
struct Args {
    /// Axum 监听地址
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,

    /// 仅供受信 Caddy 转发 Proxy Entry 控制请求的回环监听地址
    #[arg(long, default_value = "127.0.0.1:8797")]
    control_listen: SocketAddr,

    /// 与 Proxy 共用的 SQLite 用户数据库
    #[arg(long, default_value = "data/proxy-users.sqlite3")]
    database: PathBuf,

    /// Unix 下允许用户数据库及 sidecar 由文件属组只读（0640）
    #[arg(long)]
    database_group_readable: bool,

    /// 与 Proxy 共用的独立访问记录 SQLite；不得与用户数据库为同一文件
    #[arg(long, default_value = "data/proxy-access.sqlite3")]
    access_log_database: PathBuf,

    /// Unix 下允许访问记录数据库及 sidecar 由文件属组读写（0660）
    #[arg(long)]
    access_log_database_group_writable: bool,

    /// Vue 构建产物目录
    #[arg(long, default_value = "proxy-registry/frontend/dist")]
    frontend_dist: PathBuf,

    /// 明确允许在非回环地址上以明文 HTTP 监听（仅应位于受信 TLS 反向代理后）
    #[arg(long)]
    allow_insecure_remote: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();
    validate_listen_address(args.listen, args.allow_insecure_remote)?;
    if !args.control_listen.ip().is_loopback() {
        bail!(
            "Proxy 控制面必须监听回环地址并由受信 TLS 反向代理暴露，实际为 {}",
            args.control_listen
        );
    }
    let instance_id = registry_instance_id(args.listen)?;
    SqliteAccessLogRepository::validate_distinct_database_paths(
        &args.access_log_database,
        &args.database,
    )?;
    let database_file_permissions = select_database_file_permissions(
        args.database_group_readable,
        bool_env(DATABASE_GROUP_READABLE_ENV)?,
        SqliteFilePermissions::OwnerReadWriteGroupRead,
    );
    let store = Arc::new(
        SqliteUserRepository::connect_with_permissions(&args.database, database_file_permissions)
            .await?,
    );
    let access_log_file_permissions = select_database_file_permissions(
        args.access_log_database_group_writable,
        bool_env(ACCESS_LOG_DATABASE_GROUP_WRITABLE_ENV)?,
        SqliteFilePermissions::OwnerAndGroup,
    );
    let access_logs = Arc::new(
        SqliteAccessLogRepository::connect_with_permissions(
            &args.access_log_database,
            access_log_file_permissions,
        )
        .await?,
    );
    let migrated_access_rows = access_logs
        .import_legacy_user_database_once(&args.database)
        .await?;
    let access_log_settings = access_logs.get_access_log_settings().await?;
    let retention_cutoff = OffsetDateTime::now_utc().unix_timestamp()
        - i64::from(access_log_settings.retention_days) * SECONDS_PER_DAY;
    let cleaned_legacy_access_rows = access_logs
        .cleanup_legacy_user_database_access_records(&args.database, retention_cutoff)
        .await?;
    let purged_expired_access_rows = access_logs
        .purge_access_records_before(retention_cutoff)
        .await?;
    if let Err(error) = access_logs.checkpoint_wal().await {
        // Proxy may still be serving with a short read/write transaction during an ordinary Web
        // restart. Retention is already committed with secure_delete enabled, so a busy
        // checkpoint is a recoverable availability event and a later automatic/manual
        // checkpoint will truncate the WAL.
        warn!(%error, "访问记录数据库 WAL 暂时无法截断，将继续启动");
    }
    info!(
        migrated_access_rows,
        cleaned_legacy_access_rows,
        purged_expired_access_rows,
        retention_days = access_log_settings.retention_days,
        user_database = %args.database.display(),
        access_database = %args.access_log_database.display(),
        "访问记录拆库迁移、源库清理与保留期清理完成"
    );

    let master_secret = env::var(KEY_ENCRYPTION_SECRET_ENV)
        .with_context(|| format!("必须设置环境变量 {KEY_ENCRYPTION_SECRET_ENV}"))?;
    let private_keys = PrivateKeyCipher::new(&master_secret)?;
    let agent_tokens = AgentAccessTokenService::new(&master_secret)?;
    ensure_key_encryption_binding(store.as_ref(), &private_keys).await?;
    let passwords = PasswordService::new(4).await?;
    bootstrap_admin(store.as_ref(), &passwords).await?;
    let secure_cookies = bool_env(SECURE_COOKIES_ENV)?.unwrap_or(!args.listen.ip().is_loopback());
    let allow_registration =
        bool_env(ALLOW_REGISTRATION_ENV)?.unwrap_or(args.listen.ip().is_loopback());
    let trust_proxy_headers = bool_env(TRUST_PROXY_HEADERS_ENV)?.unwrap_or(false);
    if trust_proxy_headers && !args.listen.ip().is_loopback() {
        bail!("{TRUST_PROXY_HEADERS_ENV}=true 仅允许用于回环监听后的受信反向代理");
    }

    let control_token = env::var(CONTROL_TOKEN_ENV)
        .with_context(|| format!("必须设置环境变量 {CONTROL_TOKEN_ENV}"))?;
    let control_token_verifier = ControlTokenVerifier::new(&control_token)?;
    drop(control_token);
    let agent_events = proxy_registry::AgentEventHub::start(store.clone()).await?;
    let state = AppState {
        instance_id: instance_id.clone(),
        users: store.clone(),
        accounts: store.clone(),
        access_logs: access_logs.clone(),
        device_authorizations: store.clone(),
        audit_logs: store.clone(),
        proxy_addresses: store.clone(),
        passwords,
        sessions: SessionStore::new(secure_cookies),
        agent_tokens,
        agent_events: agent_events.clone(),
        web_session_handoffs: AgentWebSessionHandoffStore::new(store.clone()),
        private_keys,
        allow_registration,
        device_authorization_guard: AgentDeviceAuthorizationGuard::new(trust_proxy_headers),
    };
    let app = build_router(state, Some(args.frontend_dist));
    let control_app = build_control_router(ControlState {
        instance_id: instance_id.clone(),
        users: store.clone() as Arc<dyn UserRepository>,
        access_batches: access_logs.clone() as Arc<dyn AccessBatchRepository>,
        proxy_entries: store.clone() as Arc<dyn ProxyEntryRepository>,
        agent_events,
        token_verifier: control_token_verifier,
    });
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("无法监听 {}", args.listen))?;
    let control_listener = tokio::net::TcpListener::bind(args.control_listen)
        .await
        .with_context(|| format!("无法监听 Proxy 控制面 {}", args.control_listen))?;
    info!(
        address = %args.listen,
        control_address = %args.control_listen,
        instance_id = %instance_id,
        "PPAASS Proxy 用户管理与 Entry 控制面服务已启动"
    );
    serve_public_and_control(listener, app, control_listener, control_app).await?;
    info!("PPAASS Proxy 用户管理服务已停止");
    Ok(())
}
