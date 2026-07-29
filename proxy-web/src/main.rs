use anyhow::{Context, Result, bail};
use clap::Parser;
use protocol::RsaKeyPair;
use proxy_user_store::{
    AccessLogRepository, AccountRepository, AccountRole, AccountStatus, BootstrapOutcome,
    NewAdminAccount, SqliteAccessLogRepository, SqliteFilePermissions, SqliteUserRepository,
};
use proxy_web::{
    AgentAccessTokenService, AgentDeviceAuthorizationGuard, AppState, PasswordService,
    PrivateKeyCipher, SessionStore, build_router,
};
use rsa::traits::PublicKeyParts;
use std::{
    env,
    fs::{self, File},
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use time::OffsetDateTime;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const KEY_ENCRYPTION_SECRET_ENV: &str = "PPAASS_PROXY_WEB_KEY_ENCRYPTION_SECRET";
const BOOTSTRAP_ADMIN_USERNAME_ENV: &str = "PPAASS_PROXY_WEB_BOOTSTRAP_ADMIN_USERNAME";
const BOOTSTRAP_ADMIN_PASSWORD_ENV: &str = "PPAASS_PROXY_WEB_BOOTSTRAP_ADMIN_PASSWORD";
const ROOT_ADMIN_LOGIN_NAME: &str = "admin";
const ALLOW_REGISTRATION_ENV: &str = "PPAASS_PROXY_WEB_ALLOW_REGISTRATION";
const SECURE_COOKIES_ENV: &str = "PPAASS_PROXY_WEB_SECURE_COOKIES";
const TRUST_PROXY_HEADERS_ENV: &str = "PPAASS_PROXY_WEB_TRUST_PROXY_HEADERS";
const DATABASE_GROUP_READABLE_ENV: &str = "PPAASS_PROXY_WEB_DATABASE_GROUP_READABLE";
const ACCESS_LOG_DATABASE_GROUP_WRITABLE_ENV: &str =
    "PPAASS_PROXY_WEB_ACCESS_LOG_DATABASE_GROUP_WRITABLE";
const SECONDS_PER_DAY: i64 = 24 * 60 * 60;
const MAX_PROXY_IDENTITY_PUBLIC_KEY_BYTES: u64 = 64 * 1024;
const MIN_PROXY_IDENTITY_RSA_BITS: usize = 2048;
const MAX_PROXY_IDENTITY_RSA_BITS: usize = 8192;

#[derive(Debug, Parser)]
#[command(author, version, about = "PPAASS Proxy 用户管理 Web 服务")]
struct Args {
    /// Axum 监听地址
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,

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

    /// Proxy TCP/Yamux 传输身份的 SPKI PEM 公钥
    #[arg(long)]
    proxy_identity_public_key: PathBuf,

    /// Vue 构建产物目录
    #[arg(long, default_value = "proxy-web/frontend/dist")]
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
    let proxy_identity_public_key_pem =
        load_proxy_identity_public_key(&args.proxy_identity_public_key)?;

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

    let state = AppState {
        users: store.clone(),
        accounts: store.clone(),
        access_logs,
        device_authorizations: store,
        passwords,
        sessions: SessionStore::new(secure_cookies),
        agent_tokens,
        private_keys,
        proxy_identity_public_key_pem,
        allow_registration,
        device_authorization_guard: AgentDeviceAuthorizationGuard::new(trust_proxy_headers),
    };
    let app = build_router(state, Some(args.frontend_dist));
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("无法监听 {}", args.listen))?;
    info!(address = %args.listen, "PPAASS Proxy 用户管理服务已启动");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    info!("PPAASS Proxy 用户管理服务已停止");
    Ok(())
}

fn load_proxy_identity_public_key(path: &Path) -> Result<Arc<str>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("无法读取 Proxy 传输身份公钥文件元数据：{}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("Proxy 传输身份公钥路径必须是普通文件：{}", path.display());
    }
    if metadata.len() > MAX_PROXY_IDENTITY_PUBLIC_KEY_BYTES {
        bail!(
            "Proxy 传输身份公钥文件超过 {} 字节上限：{}",
            MAX_PROXY_IDENTITY_PUBLIC_KEY_BYTES,
            path.display()
        );
    }

    let file = File::open(path)
        .with_context(|| format!("无法打开 Proxy 传输身份公钥文件：{}", path.display()))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(usize::MAX)
            .min(MAX_PROXY_IDENTITY_PUBLIC_KEY_BYTES as usize),
    );
    file.take(MAX_PROXY_IDENTITY_PUBLIC_KEY_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("无法读取 Proxy 传输身份公钥文件：{}", path.display()))?;
    if bytes.len() as u64 > MAX_PROXY_IDENTITY_PUBLIC_KEY_BYTES {
        bail!(
            "Proxy 传输身份公钥文件超过 {} 字节上限：{}",
            MAX_PROXY_IDENTITY_PUBLIC_KEY_BYTES,
            path.display()
        );
    }
    let pem = String::from_utf8(bytes)
        .with_context(|| format!("Proxy 传输身份公钥文件不是 UTF-8：{}", path.display()))?;
    let pem = pem.trim();
    let public_key = RsaKeyPair::from_public_key_pem(pem)
        .with_context(|| format!("Proxy 传输身份公钥不是有效 SPKI PEM：{}", path.display()))?;
    let bits = public_key.n().bits();
    if !(MIN_PROXY_IDENTITY_RSA_BITS..=MAX_PROXY_IDENTITY_RSA_BITS).contains(&bits) {
        bail!(
            "Proxy 传输身份 RSA 公钥必须为 {MIN_PROXY_IDENTITY_RSA_BITS}..={MAX_PROXY_IDENTITY_RSA_BITS} 位：{}",
            path.display()
        );
    }
    Ok(Arc::from(pem))
}

async fn ensure_key_encryption_binding(
    store: &dyn AccountRepository,
    private_keys: &PrivateKeyCipher,
) -> Result<()> {
    let binding = store.key_encryption_binding().await?;
    let has_encrypted_keys = binding.sample_private_key.is_some();
    if let Some(sample) = binding.sample_private_key {
        let plaintext = private_keys
            .decrypt(
                &sample.username,
                sample.key_version,
                &sample.encrypted_private_key,
            )
            .with_context(|| {
                format!(
                    "当前私钥加密主密钥无法解密数据库中的用户 {}；请恢复与数据库匹配的主密钥",
                    sample.username
                )
            })?;
        drop(plaintext);
    }

    let verifier = match binding.verifier {
        Some(verifier) => verifier,
        None => {
            let candidate = private_keys.create_verifier()?;
            store.initialize_key_encryption_verifier(&candidate).await?
        }
    };
    private_keys
        .verify_verifier(&verifier)
        .context("当前私钥加密主密钥与数据库绑定不匹配；请恢复成组备份的数据库和主密钥")?;
    info!(has_encrypted_keys, "Proxy Web 私钥加密主密钥绑定检查完成");
    Ok(())
}

async fn bootstrap_admin(store: &SqliteUserRepository, passwords: &PasswordService) -> Result<()> {
    if let Ok(configured) = env::var(BOOTSTRAP_ADMIN_USERNAME_ENV)
        && configured.trim() != ROOT_ADMIN_LOGIN_NAME
    {
        bail!(
            "根管理员登录名固定为 {ROOT_ADMIN_LOGIN_NAME}；\
             {BOOTSTRAP_ADMIN_USERNAME_ENV} 只能设为 {ROOT_ADMIN_LOGIN_NAME}"
        );
    }
    if let Some(root) = store.get_account_by_login(ROOT_ADMIN_LOGIN_NAME).await? {
        if root.role != AccountRole::Admin || root.status != AccountStatus::Active {
            bail!("根管理员 admin 已存在但不是启用的管理员，请先修复数据库账号状态");
        }
        info!("数据库已有启用的根管理员 admin，跳过 bootstrap");
        return Ok(());
    }

    let password = env::var(BOOTSTRAP_ADMIN_PASSWORD_ENV).with_context(|| {
        format!("数据库还没有根管理员 admin；请设置 {BOOTSTRAP_ADMIN_PASSWORD_ENV}")
    })?;
    let password_hash = passwords.hash_password(password).await?;
    match store
        .bootstrap_admin_if_absent(NewAdminAccount {
            account_id: format!("acc_{}", random_account_suffix()),
            login_name: ROOT_ADMIN_LOGIN_NAME.to_string(),
            password_hash: Some(password_hash),
            display_name: Some("系统管理员".to_string()),
            email: None,
            avatar_url: None,
        })
        .await?
    {
        BootstrapOutcome::Created(account) => {
            info!(
                login_name = account.login_name,
                "已创建根管理员账号；bootstrap 密码不会覆盖已有账号"
            );
        }
        BootstrapOutcome::AlreadyExists => {
            info!("并发启动期间另一实例已创建管理员账号");
        }
    }
    let root = store
        .get_account_by_login(ROOT_ADMIN_LOGIN_NAME)
        .await?
        .context("bootstrap 完成后根管理员 admin 仍不存在")?;
    if root.role != AccountRole::Admin || root.status != AccountStatus::Active {
        bail!("根管理员 admin 必须保持管理员角色和启用状态");
    }
    Ok(())
}

fn random_account_suffix() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngExt;

    let mut bytes = [0_u8; 24];
    rand::rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn bool_env(name: &str) -> Result<Option<bool>> {
    let Some(value) = env::var(name).ok() else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => bail!("环境变量 {name} 必须是 true/false、1/0、yes/no 或 on/off"),
    }
}

fn select_database_file_permissions(
    cli_enabled: bool,
    env_enabled: Option<bool>,
    enabled_permissions: SqliteFilePermissions,
) -> SqliteFilePermissions {
    if cli_enabled || env_enabled.unwrap_or(false) {
        enabled_permissions
    } else {
        SqliteFilePermissions::OwnerOnly
    }
}

fn validate_listen_address(address: SocketAddr, allow_insecure_remote: bool) -> Result<()> {
    if !address.ip().is_loopback() && !allow_insecure_remote {
        bail!(
            "拒绝在非回环地址 {address} 上以明文 HTTP 启动；请使用 TLS 反向代理，\
             并在确认网络边界后显式添加 --allow-insecure-remote"
        );
    }
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("proxy_web=debug,proxy_user_store=debug,tower_http=info")
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .init();
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "监听 Ctrl-C 失败");
    }
}

#[cfg(test)]
#[path = "main/tests.rs"]
mod tests;
