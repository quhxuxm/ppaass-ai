use super::user_config::UserConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersConfig {
    pub users: HashMap<String, UserConfig>,
}

#[allow(dead_code)]
impl UsersConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: UsersConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}
