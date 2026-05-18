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

        if let Some(parent) = users_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }

        if !users_path.exists() {
            fs::write(&users_path, "[users]\n")?;
        }

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
        Ok(self.users.read().users.get(username).cloned())
    }

    #[instrument(skip(self))]
    pub async fn list_users(&self) -> Result<Vec<String>> {
        Ok(self.users.read().users.keys().cloned().collect())
    }
}

fn load_users(path: &Path) -> Result<UsersConfig> {
    UsersConfig::load(path).map_err(|e| {
        ProxyError::Configuration(format!("读取用户配置 {} 失败：{e}", path.display()))
    })
}

fn validate_users(users: &UsersConfig) -> Result<()> {
    for (key, user) in &users.users {
        let normalized_username = normalize_username(user.username.clone())?;
        if key != &normalized_username {
            return Err(ProxyError::Configuration(format!(
                "用户配置键 {key} 与 username 字段 {} 不一致",
                user.username
            )));
        }
    }
    Ok(())
}

fn normalize_username(username: String) -> Result<String> {
    let username = username.trim();
    if username.is_empty() {
        return Err(ProxyError::Configuration("用户名不能为空".to_string()));
    }
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
