use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub api_addr: String,
    pub users_config_path: String,
    pub keys_dir: String,

    #[serde(default)]
    pub console_port: Option<u16>,

    #[serde(default = "default_max_connections")]
    pub max_connections_per_user: usize,

    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_max_connections() -> usize {
    100
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub username: String,
    pub public_key_pem: String,

    #[serde(default)]
    pub bandwidth_limit_mbps: Option<u64>, // Megabits per second

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersConfig {
    pub users: HashMap<String, UserConfig>,
}

impl ProxyConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: ProxyConfig = toml::from_str(&content)?;
        Ok(config)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn parse_valid_users_config_with_single_user() {
        let content = r#"
[users.user1]
username = "user1"
public_key_pem = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtm6UwXI/ZmUrWPF9gkXs
-----END PUBLIC KEY-----
"""
bandwidth_limit_mbps = 100
max_connections = 50
"#;
        let file = create_temp_file(content);
        let config = UsersConfig::load(file.path()).unwrap();

        assert_eq!(config.users.len(), 1);
        assert!(config.users.contains_key("user1"));

        let user = config.users.get("user1").unwrap();
        assert_eq!(user.username, "user1");
        assert_eq!(user.bandwidth_limit_mbps, Some(100));
        assert_eq!(user.max_connections, 50);
        assert!(user.public_key_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn parse_valid_users_config_with_multiple_users() {
        let content = r#"
[users.user1]
username = "user1"
public_key_pem = "-----BEGIN PUBLIC KEY-----\nKEY1\n-----END PUBLIC KEY-----"
bandwidth_limit_mbps = 100
max_connections = 50

[users.user2]
username = "user2"
public_key_pem = "-----BEGIN PUBLIC KEY-----\nKEY2\n-----END PUBLIC KEY-----"
bandwidth_limit_mbps = 50
max_connections = 25
"#;
        let file = create_temp_file(content);
        let config = UsersConfig::load(file.path()).unwrap();

        assert_eq!(config.users.len(), 2);
        assert!(config.users.contains_key("user1"));
        assert!(config.users.contains_key("user2"));

        let user1 = config.users.get("user1").unwrap();
        assert_eq!(user1.bandwidth_limit_mbps, Some(100));

        let user2 = config.users.get("user2").unwrap();
        assert_eq!(user2.bandwidth_limit_mbps, Some(50));
        assert_eq!(user2.max_connections, 25);
    }

    #[test]
    fn parse_users_config_with_optional_bandwidth_limit() {
        let content = r#"
[users.user1]
username = "user1"
public_key_pem = "-----BEGIN PUBLIC KEY-----\nKEY\n-----END PUBLIC KEY-----"
max_connections = 50
"#;
        let file = create_temp_file(content);
        let config = UsersConfig::load(file.path()).unwrap();

        let user = config.users.get("user1").unwrap();
        assert_eq!(user.bandwidth_limit_mbps, None);
    }

    #[test]
    fn parse_users_config_with_default_max_connections() {
        let content = r#"
[users.user1]
username = "user1"
public_key_pem = "-----BEGIN PUBLIC KEY-----\nKEY\n-----END PUBLIC KEY-----"
"#;
        let file = create_temp_file(content);
        let config = UsersConfig::load(file.path()).unwrap();

        let user = config.users.get("user1").unwrap();
        assert_eq!(user.max_connections, 100);
    }

    #[test]
    fn parse_empty_users_config() {
        let content = "[users]";
        let file = create_temp_file(content);
        let config = UsersConfig::load(file.path()).unwrap();

        assert!(config.users.is_empty());
    }

    #[test]
    fn save_and_load_users_config_roundtrip() {
        let mut users = HashMap::new();
        users.insert(
            "testuser".to_string(),
            UserConfig {
                username: "testuser".to_string(),
                public_key_pem: "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----".to_string(),
                bandwidth_limit_mbps: Some(200),
                max_connections: 75,
            },
        );
        let original = UsersConfig { users };

        let file = NamedTempFile::new().unwrap();
        original.save(file.path()).unwrap();
        let loaded = UsersConfig::load(file.path()).unwrap();

        assert_eq!(loaded.users.len(), 1);
        let user = loaded.users.get("testuser").unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.bandwidth_limit_mbps, Some(200));
        assert_eq!(user.max_connections, 75);
    }

    #[test]
    fn load_nonexistent_file_returns_error() {
        let result = UsersConfig::load("/nonexistent/path/users.toml");
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_toml_returns_error() {
        let content = "this is not valid toml {{{";
        let file = create_temp_file(content);
        let result = UsersConfig::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn parse_users_config_missing_required_field_returns_error() {
        let content = r#"
[users.user1]
username = "user1"
"#;
        let file = create_temp_file(content);
        let result = UsersConfig::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn parse_proxy_config_with_all_fields() {
        let content = r#"
listen_addr = "0.0.0.0:8080"
api_addr = "0.0.0.0:8081"
users_config_path = "config/users.toml"
keys_dir = "keys"
max_connections_per_user = 200
console_port = 6670
"#;
        let file = create_temp_file(content);
        let config = ProxyConfig::load(file.path()).unwrap();

        assert_eq!(config.listen_addr, "0.0.0.0:8080");
        assert_eq!(config.api_addr, "0.0.0.0:8081");
        assert_eq!(config.users_config_path, "config/users.toml");
        assert_eq!(config.keys_dir, "keys");
        assert_eq!(config.max_connections_per_user, 200);
        assert_eq!(config.console_port, Some(6670));
    }

    #[test]
    fn parse_proxy_config_with_default_max_connections() {
        let content = r#"
listen_addr = "0.0.0.0:8080"
api_addr = "0.0.0.0:8081"
users_config_path = "config/users.toml"
keys_dir = "keys"
"#;
        let file = create_temp_file(content);
        let config = ProxyConfig::load(file.path()).unwrap();

        assert_eq!(config.max_connections_per_user, 100);
        assert_eq!(config.console_port, None);
    }

    #[test]
    fn parse_proxy_config_missing_required_field_returns_error() {
        let content = r#"
listen_addr = "0.0.0.0:8080"
"#;
        let file = create_temp_file(content);
        let result = ProxyConfig::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn user_config_public_key_preserves_multiline_format() {
        let content = r#"
[users.user1]
username = "user1"
public_key_pem = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtm6UwXI/ZmUrWPF9gkXs
vmnh/77vci16aGJBZv9BM7+wuY2ml7mvdYFbGVPiKB9LC4tudvGmv298XuecKxuz
-----END PUBLIC KEY-----
"""
"#;
        let file = create_temp_file(content);
        let config = UsersConfig::load(file.path()).unwrap();

        let user = config.users.get("user1").unwrap();
        assert!(user.public_key_pem.contains('\n'));
        assert!(user.public_key_pem.starts_with('\n') || user.public_key_pem.starts_with("-----BEGIN"));
    }
}
