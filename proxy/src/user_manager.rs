use crate::config::UserConfig;
use crate::entity::user;
use crate::error::{ProxyError, Result};
use protocol::crypto::RsaKeyPair;
use sea_orm::*;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, instrument};

pub struct UserManager {
    db: DatabaseConnection,
    keys_dir: PathBuf,
}

impl UserManager {
    #[instrument(skip(database_path, keys_dir))]
    pub async fn new<P: AsRef<Path>>(database_path: P, keys_dir: P) -> Result<Self> {
        let database_path = database_path.as_ref();
        let keys_dir = keys_dir.as_ref().to_path_buf();

        // Create keys directory if it doesn't exist
        fs::create_dir_all(&keys_dir)?;

        // Create parent directory for database if it doesn't exist
        if let Some(parent) = database_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Connect to SQLite database
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());
        let db = Database::connect(&database_url).await?;

        // Create table if not exists
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

        info!("Connected to SQLite database: {}", database_path.display());

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
        info!("Adding user: {}", username);

        // Generate RSA key pair
        let keypair = RsaKeyPair::generate(2048)?;
        let private_key_pem = keypair.private_key_to_pem()?;
        let public_key_pem = keypair.public_key_to_pem()?;

        // Save private key to file
        let private_key_path = self.keys_dir.join(format!("{}.pem", username));
        fs::write(&private_key_path, &private_key_pem)?;

        // Create user in database
        let now = chrono::Utc::now().naive_utc();
        let user = user::ActiveModel {
            username: Set(username.clone()),
            public_key_pem: Set(public_key_pem.clone()),
            bandwidth_limit_mbps: Set(bandwidth_limit_mbps.map(|v| v as i64)),
            created_at: Set(now),
            updated_at: Set(now),
        };

        user::Entity::insert(user).exec(&self.db).await?;

        info!("User {} added successfully", username);
        Ok((private_key_pem, public_key_pem))
    }

    #[instrument(skip(self))]
    pub async fn remove_user(&self, username: &str) -> Result<()> {
        info!("Removing user: {}", username);

        let result = user::Entity::delete_by_id(username.to_string())
            .exec(&self.db)
            .await?;

        if result.rows_affected == 0 {
            return Err(ProxyError::UserNotFound(username.to_string()));
        }

        // Delete private key file
        let private_key_path = self.keys_dir.join(format!("{}.pem", username));
        if private_key_path.exists() {
            fs::remove_file(private_key_path)?;
        }

        info!("User {} removed successfully", username);
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn list_users(&self) -> Result<Vec<String>> {
        let users = user::Entity::find().all(&self.db).await?;
        Ok(users.into_iter().map(|u| u.username).collect())
    }

    /// Import a user with an existing public key (for migration from TOML config)
    #[instrument(skip(self))]
    pub async fn import_user(
        &self,
        username: String,
        public_key_pem: String,
        bandwidth_limit_mbps: Option<u64>,
    ) -> Result<()> {
        info!("Importing user: {}", username);

        // Create user in database
        let now = chrono::Utc::now().naive_utc();
        let user = user::ActiveModel {
            username: Set(username.clone()),
            public_key_pem: Set(public_key_pem),
            bandwidth_limit_mbps: Set(bandwidth_limit_mbps.map(|v| v as i64)),
            created_at: Set(now),
            updated_at: Set(now),
        };

        user::Entity::insert(user).exec(&self.db).await?;

        info!("User {} imported successfully", username);
        Ok(())
    }

    #[allow(dead_code)]
    #[instrument(skip(self))]
    pub async fn update_user_bandwidth(
        &self,
        username: &str,
        bandwidth_limit_mbps: Option<u64>,
    ) -> Result<()> {
        info!("Updating bandwidth for user: {}", username);

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
                info!("User {} bandwidth updated successfully", username);
                Ok(())
            }
            None => Err(ProxyError::UserNotFound(username.to_string())),
        }
    }
}
