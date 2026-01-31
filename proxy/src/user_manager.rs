use crate::config::{UserConfig, UsersConfig};
use crate::error::{ProxyError, Result};
use dashmap::DashMap;
use protocol::crypto::RsaKeyPair;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info};

pub struct UserManager {
    users: Arc<DashMap<String, UserConfig>>,
    users_config_path: PathBuf,
    keys_dir: PathBuf,
    active_connections: Arc<DashMap<String, usize>>, // Track active connections per user
}

impl UserManager {
    pub fn new<P: AsRef<Path>>(users_config_path: P, keys_dir: P) -> Result<Self> {
        let users_config_path = users_config_path.as_ref().to_path_buf();
        let keys_dir = keys_dir.as_ref().to_path_buf();

        // Create keys directory if it doesn't exist
        fs::create_dir_all(&keys_dir)?;

        // Load users from config
        let users = Arc::new(DashMap::new());
        let active_connections = Arc::new(DashMap::new());

        if users_config_path.exists() {
            match UsersConfig::load(&users_config_path) {
                Ok(config) => {
                    for (username, user_config) in config.users {
                        users.insert(username.clone(), user_config);
                        active_connections.insert(username, 0); // Initialize active connections to 0
                    }
                    info!("Loaded {} users from config", users.len());
                }
                Err(e) => {
                    error!("Failed to load users config: {}", e);
                }
            }
        }

        Ok(Self {
            users,
            users_config_path,
            keys_dir,
            active_connections,
        })
    }

    pub fn get_user(&self, username: &str) -> Option<UserConfig> {
        self.users.get(username).map(|entry| entry.value().clone())
    }

    pub fn add_user(
        &self,
        username: String,
        bandwidth_limit_mbps: Option<u64>,
        max_connections: usize,
    ) -> Result<(String, String)> {
        info!("Adding user: {}", username);

        // Generate RSA key pair
        let keypair = RsaKeyPair::generate(2048)?;
        let private_key_pem = keypair.private_key_to_pem()?;
        let public_key_pem = keypair.public_key_to_pem()?;

        // Save private key to file
        let private_key_path = self.keys_dir.join(format!("{}.pem", username));
        fs::write(&private_key_path, &private_key_pem)?;

        // Create user config
        let user_config = UserConfig {
            username: username.clone(),
            public_key_pem: public_key_pem.clone(),
            bandwidth_limit_mbps,
            max_connections,
        };

        self.users.insert(username.clone(), user_config);

        // Save to config file
        self.save_config()?;

        info!("User {} added successfully", username);
        Ok((private_key_pem, public_key_pem))
    }

    pub fn remove_user(&self, username: &str) -> Result<()> {
        info!("Removing user: {}", username);

        if self.users.remove(username).is_none() {
            return Err(ProxyError::UserNotFound(username.to_string()));
        }

        // Delete private key file
        let private_key_path = self.keys_dir.join(format!("{}.pem", username));
        if private_key_path.exists() {
            fs::remove_file(private_key_path)?;
        }

        // Save to config file
        self.save_config()?;

        info!("User {} removed successfully", username);
        Ok(())
    }

    pub fn list_users(&self) -> Vec<String> {
        self.users.iter().map(|entry| entry.key().clone()).collect()
    }

    pub async fn get_active_connections(&self, username: &str) -> usize {
        self.active_connections
            .get(username)
            .map(|r| *r)
            .unwrap_or(0)
    }

    pub async fn increment_active_connections(&self, username: &str) -> Result<()> {
        let mut count = self
            .active_connections
            .entry(username.to_string())
            .or_insert(0);
        *count += 1;
        Ok(())
    }

    pub async fn decrement_active_connections(&self, username: &str) -> Result<()> {
        let mut count = self
            .active_connections
            .entry(username.to_string())
            .or_insert(0);
        if *count > 0 {
            *count -= 1;
        }
        Ok(())
    }

    fn save_config(&self) -> Result<()> {
        let users_map: std::collections::HashMap<String, UserConfig> = self
            .users
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        let users_config = UsersConfig { users: users_map };
        users_config
            .save(&self.users_config_path)
            .map_err(|e| ProxyError::Io(std::io::Error::other(e)))?;

        Ok(())
    }
}
