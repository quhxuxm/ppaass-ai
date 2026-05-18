use crate::config::{UserConfig, UsersConfig};
use crate::error::{ProxyError, Result};
use parking_lot::RwLock;
use protocol::crypto::RsaKeyPair;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, instrument};

pub struct UserManager {
    users_path: PathBuf,
    keys_dir: PathBuf,
    users: RwLock<UsersConfig>,
}

impl UserManager {
    #[instrument(skip(users_path, keys_dir))]
    pub fn new<P: AsRef<Path>>(users_path: P, keys_dir: P) -> Result<Self> {
        let users_path = users_path.as_ref().to_path_buf();
        let keys_dir = keys_dir.as_ref().to_path_buf();

        if let Some(parent) = users_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&keys_dir)?;

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
            users_path,
            keys_dir,
            users: RwLock::new(users),
        })
    }

    #[instrument(skip(self))]
    pub async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        Ok(self.users.read().users.get(username).cloned())
    }

    #[instrument(skip(self))]
    pub async fn add_user(
        &self,
        username: String,
        bandwidth_limit_mbps: Option<u64>,
    ) -> Result<(String, String)> {
        let username = normalize_username(username)?;
        info!("正在添加用户：{}", username);

        let mut users = self.users.write();
        if users.users.contains_key(&username) {
            return Err(ProxyError::UserAlreadyExists(username));
        }

        let keypair = RsaKeyPair::generate(2048)?;
        let private_key_pem = keypair.private_key_to_pem()?;
        let public_key_pem = keypair.public_key_to_pem()?;

        let private_key_path = self.private_key_path(&username);
        fs::write(&private_key_path, &private_key_pem)?;

        users.users.insert(
            username.clone(),
            UserConfig {
                username: username.clone(),
                public_key_pem: public_key_pem.clone(),
                bandwidth_limit_mbps,
            },
        );

        if let Err(err) = save_users(&self.users_path, &users) {
            users.users.remove(&username);
            let _ = fs::remove_file(&private_key_path);
            return Err(err);
        }

        info!(
            "用户 {} 添加成功，已写入 {}",
            username,
            self.users_path.display()
        );
        Ok((private_key_pem, public_key_pem))
    }

    #[instrument(skip(self))]
    pub async fn remove_user(&self, username: &str) -> Result<()> {
        info!("正在删除用户：{}", username);

        let mut users = self.users.write();
        let Some(removed) = users.users.remove(username) else {
            return Err(ProxyError::UserNotFound(username.to_string()));
        };

        if let Err(err) = save_users(&self.users_path, &users) {
            users.users.insert(username.to_string(), removed);
            return Err(err);
        }

        let private_key_path = self.private_key_path(username);
        if private_key_path.exists() {
            fs::remove_file(private_key_path)?;
        }

        info!(
            "用户 {} 删除成功，已写入 {}",
            username,
            self.users_path.display()
        );
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn list_users(&self) -> Result<Vec<String>> {
        Ok(self.users.read().users.keys().cloned().collect())
    }

    #[allow(dead_code)]
    #[instrument(skip(self))]
    pub async fn update_user_bandwidth(
        &self,
        username: &str,
        bandwidth_limit_mbps: Option<u64>,
    ) -> Result<()> {
        info!("正在更新用户 {} 的带宽限制", username);

        let mut users = self.users.write();
        let Some(user) = users.users.get_mut(username) else {
            return Err(ProxyError::UserNotFound(username.to_string()));
        };

        let previous = user.bandwidth_limit_mbps;
        user.bandwidth_limit_mbps = bandwidth_limit_mbps;
        if let Err(err) = save_users(&self.users_path, &users) {
            if let Some(user) = users.users.get_mut(username) {
                user.bandwidth_limit_mbps = previous;
            }
            return Err(err);
        }

        info!("用户 {} 的带宽限制更新成功", username);
        Ok(())
    }

    fn private_key_path(&self, username: &str) -> PathBuf {
        self.keys_dir.join(format!("{username}.pem"))
    }
}

fn load_users(path: &Path) -> Result<UsersConfig> {
    UsersConfig::load(path).map_err(|e| {
        ProxyError::Configuration(format!("读取用户配置 {} 失败：{e}", path.display()))
    })
}

fn save_users(path: &Path, users: &UsersConfig) -> Result<()> {
    users.save(path).map_err(|e| {
        ProxyError::Configuration(format!("写入用户配置 {} 失败：{e}", path.display()))
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
