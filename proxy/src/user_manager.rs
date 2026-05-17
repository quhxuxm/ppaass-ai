use crate::config::UserConfig;
use crate::entity::user;
use crate::error::{ProxyError, Result};
use protocol::crypto::RsaKeyPair;
use sea_orm::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, instrument};

use crate::config::DatabasePoolConfig;

pub struct UserManager {
    db: DatabaseConnection,
    keys_dir: PathBuf,
}

impl UserManager {
    #[instrument(skip(database_path, keys_dir, db_pool_config))]
    pub async fn new<P: AsRef<Path>>(
        database_path: P,
        keys_dir: P,
        db_pool_config: &DatabasePoolConfig,
    ) -> Result<Self> {
        let database_path = database_path.as_ref();
        let keys_dir = keys_dir.as_ref().to_path_buf();

        // 如果密钥目录不存在，则创建
        fs::create_dir_all(&keys_dir)?;

        // 如果数据库父目录不存在，则创建
        if let Some(parent) = database_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // 使用配置中的连接池参数连接 SQLite 数据库
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());
        let mut opt = ConnectOptions::new(database_url);
        opt.max_connections(db_pool_config.max_connections)
            .min_connections(db_pool_config.min_connections)
            .connect_timeout(Duration::from_secs(db_pool_config.connect_timeout_secs))
            .idle_timeout(Duration::from_secs(db_pool_config.idle_timeout_secs))
            .max_lifetime(Duration::from_secs(db_pool_config.max_lifetime_secs))
            .sqlx_logging(false);

        let db = Database::connect(opt).await?;

        // 如果表不存在，则创建
        let create_table_sql = r#"
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY NOT NULL,
                public_key_pem TEXT NOT NULL,
                bandwidth_limit_mbps INTEGER,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        "#;
        db.execute(Statement::from_string(
            db.get_database_backend(),
            create_table_sql.to_string(),
        ))
        .await?;

        info!("已连接到 SQLite 数据库：{}", database_path.display());

        Ok(Self { db, keys_dir })
    }

    #[instrument(skip(self))]
    pub async fn get_user(&self, username: &str) -> Result<Option<UserConfig>> {
        let user = user::Entity::find_by_id(username.to_string())
            .one(&self.db)
            .await?;

        Ok(user.map(|u| UserConfig {
            username: u.username,
            public_key_pem: u.public_key_pem,
            bandwidth_limit_mbps: u.bandwidth_limit_mbps.map(|v| v as u64),
        }))
    }

    #[instrument(skip(self))]
    pub async fn add_user(
        &self,
        username: String,
        bandwidth_limit_mbps: Option<u64>,
    ) -> Result<(String, String)> {
        info!("正在添加用户：{}", username);

        // 生成 RSA 密钥对
        let keypair = RsaKeyPair::generate(2048)?;
        let private_key_pem = keypair.private_key_to_pem()?;
        let public_key_pem = keypair.public_key_to_pem()?;

        // 将私钥保存到文件
        let private_key_path = self.keys_dir.join(format!("{}.pem", username));
        fs::write(&private_key_path, &private_key_pem)?;

        // 在数据库中创建用户
        let now = chrono::Utc::now().naive_utc();
        let user = user::ActiveModel {
            username: Set(username.clone()),
            public_key_pem: Set(public_key_pem.clone()),
            bandwidth_limit_mbps: Set(bandwidth_limit_mbps.map(|v| v as i64)),
            created_at: Set(now),
            updated_at: Set(now),
        };

        user::Entity::insert(user).exec(&self.db).await?;

        info!("用户 {} 添加成功", username);
        Ok((private_key_pem, public_key_pem))
    }

    #[instrument(skip(self))]
    pub async fn remove_user(&self, username: &str) -> Result<()> {
        info!("正在删除用户：{}", username);

        let result = user::Entity::delete_by_id(username.to_string())
            .exec(&self.db)
            .await?;

        if result.rows_affected == 0 {
            return Err(ProxyError::UserNotFound(username.to_string()));
        }

        // 删除私钥文件
        let private_key_path = self.keys_dir.join(format!("{}.pem", username));
        if private_key_path.exists() {
            fs::remove_file(private_key_path)?;
        }

        info!("用户 {} 删除成功", username);
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn list_users(&self) -> Result<Vec<String>> {
        let users = user::Entity::find().all(&self.db).await?;
        Ok(users.into_iter().map(|u| u.username).collect())
    }

    /// 使用现有公钥导入用户（用于从 TOML 配置迁移）
    #[instrument(skip(self))]
    pub async fn import_user(
        &self,
        username: String,
        public_key_pem: String,
        bandwidth_limit_mbps: Option<u64>,
    ) -> Result<()> {
        info!("正在导入用户：{}", username);

        // 在数据库中创建用户
        let now = chrono::Utc::now().naive_utc();
        let user = user::ActiveModel {
            username: Set(username.clone()),
            public_key_pem: Set(public_key_pem),
            bandwidth_limit_mbps: Set(bandwidth_limit_mbps.map(|v| v as i64)),
            created_at: Set(now),
            updated_at: Set(now),
        };

        user::Entity::insert(user).exec(&self.db).await?;

        info!("用户 {} 导入成功", username);
        Ok(())
    }

    #[allow(dead_code)]
    #[instrument(skip(self))]
    pub async fn update_user_bandwidth(
        &self,
        username: &str,
        bandwidth_limit_mbps: Option<u64>,
    ) -> Result<()> {
        info!("正在更新用户 {} 的带宽限制", username);

        let user = user::Entity::find_by_id(username.to_string())
            .one(&self.db)
            .await?;

        match user {
            Some(_) => {
                let now = chrono::Utc::now().naive_utc();
                let update = user::ActiveModel {
                    username: Set(username.to_string()),
                    bandwidth_limit_mbps: Set(bandwidth_limit_mbps.map(|v| v as i64)),
                    updated_at: Set(now),
                    ..Default::default()
                };
                user::Entity::update(update).exec(&self.db).await?;
                info!("用户 {} 的带宽限制更新成功", username);
                Ok(())
            }
            None => Err(ProxyError::UserNotFound(username.to_string())),
        }
    }
}
