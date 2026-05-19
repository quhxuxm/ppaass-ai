use super::user_config::UserConfig;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersConfig {
    pub users: BTreeMap<String, UserConfig>,
}

impl UsersConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        // users.toml 使用 BTreeMap，保证用户枚举和序列化顺序稳定。
        let content = fs::read_to_string(path)?;
        let config: UsersConfig = toml::from_str(&content)?;
        Ok(config)
    }
}
