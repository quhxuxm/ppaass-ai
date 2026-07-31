use super::*;
use protocol::RsaKeyPair;
use rsa::traits::PublicKeyParts;
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};
use tracing_subscriber::EnvFilter;

pub(super) fn load_proxy_identity_public_key(path: &Path) -> Result<Arc<str>> {
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

pub(super) async fn ensure_key_encryption_binding(
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
    info!(
        has_encrypted_keys,
        "Proxy Registry 私钥加密主密钥绑定检查完成"
    );
    Ok(())
}

pub(super) async fn bootstrap_admin(
    store: &SqliteUserRepository,
    passwords: &PasswordService,
) -> Result<()> {
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
        BootstrapOutcome::AlreadyExists => info!("并发启动期间另一实例已创建管理员账号"),
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

pub(super) fn bool_env(name: &str) -> Result<Option<bool>> {
    let Some(value) = env::var(name).ok() else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => bail!("环境变量 {name} 必须是 true/false、1/0、yes/no 或 on/off"),
    }
}

pub(super) fn select_database_file_permissions(
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

pub(super) fn validate_listen_address(
    address: SocketAddr,
    allow_insecure_remote: bool,
) -> Result<()> {
    if !address.ip().is_loopback() && !allow_insecure_remote {
        bail!(
            "拒绝在非回环地址 {address} 上以明文 HTTP 启动；请使用 TLS 反向代理，\
             并在确认网络边界后显式添加 --allow-insecure-remote"
        );
    }
    Ok(())
}

pub(super) fn registry_instance_id(listen: SocketAddr) -> Result<Arc<str>> {
    let value = match env::var(INSTANCE_ID_ENV) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => format!("registry-{}", listen.port()),
        Err(env::VarError::NotUnicode(_)) => {
            bail!("环境变量 {INSTANCE_ID_ENV} 必须是有效 UTF-8")
        }
    };
    let value = value.trim();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("环境变量 {INSTANCE_ID_ENV} 必须为 1..=64 个 ASCII 字母、数字、点、下划线或连字符");
    }
    Ok(Arc::from(value))
}

pub(super) fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("proxy_registry=debug,tower_http=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .init();
}
