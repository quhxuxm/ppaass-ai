use anyhow::{Context, Result, bail};
use clap::Parser;
use proxy_user_store::{
    AccountRepository, BootstrapOutcome, NewAdminAccount, SqliteUserRepository,
};
use proxy_web::{
    AppState, OAuthService, PasswordService, PrivateKeyCipher, SessionStore, build_router,
};
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use tracing::info;
use tracing_subscriber::EnvFilter;

const KEY_ENCRYPTION_SECRET_ENV: &str = "PPAASS_PROXY_WEB_KEY_ENCRYPTION_SECRET";
const BOOTSTRAP_ADMIN_USERNAME_ENV: &str = "PPAASS_PROXY_WEB_BOOTSTRAP_ADMIN_USERNAME";
const BOOTSTRAP_ADMIN_PASSWORD_ENV: &str = "PPAASS_PROXY_WEB_BOOTSTRAP_ADMIN_PASSWORD";
const ALLOW_REGISTRATION_ENV: &str = "PPAASS_PROXY_WEB_ALLOW_REGISTRATION";
const SECURE_COOKIES_ENV: &str = "PPAASS_PROXY_WEB_SECURE_COOKIES";

#[derive(Debug, Parser)]
#[command(author, version, about = "PPAASS Proxy 用户管理 Web 服务")]
struct Args {
    /// Axum 监听地址
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,

    /// 与 Proxy 共用的 SQLite 用户数据库
    #[arg(long, default_value = "data/proxy-users.sqlite3")]
    database: PathBuf,

    /// 数据库首次初始化时导入的 users.toml
    #[arg(long, default_value = "config/local/users.toml")]
    users_toml: PathBuf,

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

    let store = Arc::new(SqliteUserRepository::connect(&args.database).await?);
    let import_outcome = store.import_users_toml_once(&args.users_toml).await?;
    info!(?import_outcome, "users.toml 首次导入检查完成");

    let master_secret = env::var(KEY_ENCRYPTION_SECRET_ENV)
        .with_context(|| format!("必须设置环境变量 {KEY_ENCRYPTION_SECRET_ENV}"))?;
    let private_keys = PrivateKeyCipher::new(&master_secret)?;
    ensure_key_encryption_binding(store.as_ref(), &private_keys).await?;
    let passwords = PasswordService::new(4).await?;
    bootstrap_admin(store.as_ref(), &passwords).await?;
    let secure_cookies = bool_env(SECURE_COOKIES_ENV)?.unwrap_or(!args.listen.ip().is_loopback());
    let allow_registration = bool_env(ALLOW_REGISTRATION_ENV)?.unwrap_or(
        OAuthService::local_registration_enabled_default(args.listen.ip().is_loopback()),
    );
    let oauth = OAuthService::from_env(secure_cookies)?;

    let state = AppState {
        users: store.clone(),
        accounts: store.clone(),
        access_logs: store,
        passwords,
        sessions: SessionStore::new(secure_cookies),
        private_keys,
        oauth,
        allow_registration,
    };
    let app = build_router(state, Some(args.frontend_dist));
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("无法监听 {}", args.listen))?;
    info!(address = %args.listen, "PPAASS Proxy 用户管理服务已启动");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    info!("PPAASS Proxy 用户管理服务已停止");
    Ok(())
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
    if store.active_admin_count().await? > 0 {
        info!("数据库已有启用的管理员账号，跳过 bootstrap");
        return Ok(());
    }

    let username = env::var(BOOTSTRAP_ADMIN_USERNAME_ENV).unwrap_or_else(|_| "admin".to_string());
    let password = env::var(BOOTSTRAP_ADMIN_PASSWORD_ENV).with_context(|| {
        format!(
            "数据库还没有管理员；请设置 {BOOTSTRAP_ADMIN_PASSWORD_ENV}（用户名可通过 \
             {BOOTSTRAP_ADMIN_USERNAME_ENV} 设置，默认 admin）"
        )
    })?;
    let password_hash = passwords.hash_password(password).await?;
    match store
        .bootstrap_admin_if_none(NewAdminAccount {
            account_id: format!("acc_{}", random_account_suffix()),
            login_name: username,
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
                "已创建首个管理员账号；bootstrap 密码不会再次使用"
            );
        }
        BootstrapOutcome::AlreadyExists => {
            info!("并发启动期间另一实例已创建管理员账号");
        }
    }
    if store.active_admin_count().await? == 0 {
        bail!(
            "数据库已有管理员记录但没有启用的管理员；为避免通过环境变量静默接管，\
             请先显式恢复一个管理员账号"
        );
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
mod tests {
    use super::*;
    use protocol::RsaKeyPair;
    use proxy_user_store::{AccountRole, AccountStatus, NewManagedUser, NewUser, UserOrigin};
    use tempfile::TempDir;

    #[test]
    fn requires_explicit_opt_in_for_non_loopback_http() {
        let loopback = "127.0.0.1:8787".parse().unwrap();
        let remote = "0.0.0.0:8787".parse().unwrap();

        assert!(validate_listen_address(loopback, false).is_ok());
        assert!(validate_listen_address(remote, false).is_err());
        assert!(validate_listen_address(remote, true).is_ok());
    }

    #[tokio::test]
    async fn key_binding_migrates_existing_envelopes_and_rejects_the_wrong_secret() {
        let directory = TempDir::new().unwrap();
        let store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
            .await
            .unwrap();
        let correct =
            PrivateKeyCipher::new("correct-test-master-secret-with-at-least-32-bytes").unwrap();
        let wrong =
            PrivateKeyCipher::new("wrong-test-master-secret-with-at-least-32-bytes").unwrap();
        let public_key = RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        store
            .create_managed_user(NewManagedUser {
                account_id: "acc_alice".to_string(),
                login_name: "alice".to_string(),
                password_hash: Some("$argon2id$test".to_string()),
                role: AccountRole::User,
                status: AccountStatus::Active,
                display_name: None,
                email: None,
                avatar_url: None,
                profile: NewUser::new("alice", public_key, UserOrigin::Admin),
                encrypted_private_key: correct.encrypt("alice", 1, "private-pem").unwrap(),
                external_identity: None,
            })
            .await
            .unwrap();

        assert!(ensure_key_encryption_binding(&store, &wrong).await.is_err());
        assert!(
            store
                .key_encryption_binding()
                .await
                .unwrap()
                .verifier
                .is_none()
        );

        ensure_key_encryption_binding(&store, &correct)
            .await
            .unwrap();
        let verifier = store
            .key_encryption_binding()
            .await
            .unwrap()
            .verifier
            .unwrap();
        correct.verify_verifier(&verifier).unwrap();
        assert!(ensure_key_encryption_binding(&store, &wrong).await.is_err());
    }
}
