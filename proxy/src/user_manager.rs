use crate::config::{UserConfig, UsersConfig};
use crate::error::{ProxyError, Result};
use parking_lot::RwLock;
use proxy_user_store::UserRepository;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, instrument};

pub struct UserManager {
    source: UserSource,
}

enum UserSource {
    Toml(RwLock<UsersConfig>),
    Repository(Arc<dyn UserRepository>),
}

impl UserManager {
    #[instrument(skip(users_path, repository))]
    pub fn new<P: AsRef<Path>>(
        users_path: P,
        repository: Option<Arc<dyn UserRepository>>,
    ) -> Result<Self> {
        let users_path = users_path.as_ref().to_path_buf();

        if let Some(repository) = repository {
            info!("已启用数据库用户 Repository");
            return Ok(Self {
                source: UserSource::Repository(repository),
            });
        }

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
            source: UserSource::Toml(RwLock::new(users)),
        })
    }

    #[instrument(skip(self))]
    pub async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        match &self.source {
            // 认证路径只读用户配置，RwLock 让多个连接可以并发查询。
            UserSource::Toml(users) => Ok(users.read().users.get(username).cloned()),
            UserSource::Repository(repository) => repository
                .get_user(username)
                .await
                .map(|user| {
                    user.map(|user| UserConfig {
                        username: user.username,
                        public_key_pem: user.public_key_pem,
                        expires_at: user.expires_at.map(|timestamp| timestamp.to_string()),
                        permissions: user.permissions,
                        enabled: user.enabled,
                    })
                })
                .map_err(|error| {
                    ProxyError::Configuration(format!("查询用户 Repository 失败：{error}"))
                }),
        }
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
    // users.toml 兼容模式保留历史校验语义；数据库/API 的新用户另有长度上限。
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

#[cfg(test)]
mod tests {
    use super::UserManager;
    use protocol::RsaKeyPair;
    use proxy_user_store::{SqliteUserRepository, UserRepository};
    use std::fs;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[tokio::test]
    async fn keeps_users_toml_compatibility_without_repository() {
        let directory = TempDir::new().unwrap();
        let users_path = directory.path().join("users.toml");
        fs::write(
            &users_path,
            r#"
[users.alice]
username = "alice"
public_key_pem = "public-key"
expires_at = 1893456000
"#,
        )
        .unwrap();

        let manager = UserManager::new(&users_path, None).unwrap();
        let user = manager.get_user("alice").await.unwrap().unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.expires_at.as_deref(), Some("1893456000"));
    }

    #[tokio::test]
    async fn creates_empty_users_toml_in_compatibility_mode() {
        let directory = TempDir::new().unwrap();
        let users_path = directory.path().join("nested/users.toml");

        let manager = UserManager::new(&users_path, None).unwrap();
        assert!(manager.get_user("missing").await.unwrap().is_none());
        assert_eq!(fs::read_to_string(users_path).unwrap(), "[users]\n");
    }

    #[tokio::test]
    async fn observes_web_changes_from_the_same_sqlite_file() {
        let directory = TempDir::new().unwrap();
        let database_path = directory.path().join("users.sqlite3");
        let web_store = SqliteUserRepository::connect(&database_path).await.unwrap();
        let proxy_store = SqliteUserRepository::connect(&database_path).await.unwrap();
        let repository: Arc<dyn UserRepository> = Arc::new(proxy_store);
        let manager =
            UserManager::new(directory.path().join("unused.toml"), Some(repository)).unwrap();
        assert!(manager.get_user("alice").await.unwrap().is_none());

        let public_key = RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        web_store
            .create_user("alice", &public_key, Some(1_893_456_000))
            .await
            .unwrap();

        let user = manager.get_user("alice").await.unwrap().unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.expires_at.as_deref(), Some("1893456000"));
    }
}
