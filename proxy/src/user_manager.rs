use crate::config::{UserConfig, UsersConfig};
use crate::error::{ProxyError, Result};
use parking_lot::RwLock;
use std::fs;
use std::path::Path;
use tracing::{info, instrument};

pub struct UserManager {
    users: RwLock<UsersConfig>,
}

impl UserManager {
    #[instrument(skip(users_path))]
    pub fn new<P: AsRef<Path>>(users_path: P) -> Result<Self> {
        let users_path = users_path.as_ref().to_path_buf();

        // 用户配置允许放在尚不存在的目录下，启动时先补齐父目录。
        if let Some(parent) = users_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }

        // 首次启动时创建一个空 users.toml，让 proxy 可以用配置文件方式管理用户。
        if !users_path.exists() {
            fs::write(&users_path, "[users]\n")?;
        }

        // 加载后立即做一致性校验，避免运行中认证阶段才发现配置错误。
        let users = load_users(&users_path)?;
        validate_users(&users)?;
        info!(
            "已加载用户配置：{}（{} 个用户）",
            users_path.display(),
            users.users.len()
        );

        Ok(Self {
            users: RwLock::new(users),
        })
    }

    #[instrument(skip(self))]
    pub async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        // 认证路径只读用户配置，RwLock 让多个连接可以并发查询。
        Ok(self.users.read().users.get(username).cloned())
    }
}

fn load_users(path: &Path) -> Result<UsersConfig> {
    // 将底层 TOML/IO 错误包装成配置错误，日志里带上具体文件路径。
    UsersConfig::load(path).map_err(|e| {
        ProxyError::Configuration(format!("读取用户配置 {} 失败：{e}", path.display()))
    })
}

fn validate_users(users: &UsersConfig) -> Result<()> {
    // TOML 表键和 username 必须一致，否则认证时会出现同一用户两个名字。
    for (key, user) in &users.users {
        let normalized_username = normalize_username(user.username.clone())?;
        if key != &normalized_username {
            return Err(ProxyError::Configuration(format!(
                "用户配置键 {key} 与 username 字段 {} 不一致",
                user.username
            )));
        }
        user.expires_at_unix_timestamp()?;
    }
    Ok(())
}

fn normalize_username(username: String) -> Result<String> {
    // 用户名会出现在配置键和日志里，先去掉首尾空白并拒绝空值。
    let username = username.trim();
    if username.is_empty() {
        return Err(ProxyError::Configuration("用户名不能为空".to_string()));
    }
    // 禁止路径控制字符，为后续可能的文件化用户资产保留安全边界。
    if username.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
        || username.contains("..")
        || username.chars().any(char::is_control)
    {
        return Err(ProxyError::Configuration(format!(
            "用户名包含非法路径字符：{username}"
        )));
    }
    Ok(username.to_string())
}
