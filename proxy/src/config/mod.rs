mod proxy_config;
mod user_config;
mod users_config;

pub use proxy_config::{DatabasePoolConfig, ProxyConfig};
pub use user_config::UserConfig;
pub use users_config::UsersConfig;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
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
"#;
        let file = create_temp_file(content);
        let config = UsersConfig::load(file.path()).unwrap();

        assert_eq!(config.users.len(), 1);
        assert!(config.users.contains_key("user1"));

        let user = config.users.get("user1").unwrap();
        assert_eq!(user.username, "user1");
        assert_eq!(user.bandwidth_limit_mbps, Some(100));
        assert!(user.public_key_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn parse_valid_users_config_with_multiple_users() {
        let content = r#"
[users.user1]
username = "user1"
public_key_pem = "-----BEGIN PUBLIC KEY-----\nKEY1\n-----END PUBLIC KEY-----"
bandwidth_limit_mbps = 100

[users.user2]
username = "user2"
public_key_pem = "-----BEGIN PUBLIC KEY-----\nKEY2\n-----END PUBLIC KEY-----"
bandwidth_limit_mbps = 50
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
    }

    #[test]
    fn parse_users_config_with_optional_bandwidth_limit() {
        let content = r#"
[users.user1]
username = "user1"
public_key_pem = "-----BEGIN PUBLIC KEY-----\nKEY\n-----END PUBLIC KEY-----"
"#;
        let file = create_temp_file(content);
        let config = UsersConfig::load(file.path()).unwrap();

        let user = config.users.get("user1").unwrap();
        assert_eq!(user.bandwidth_limit_mbps, None);
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
                public_key_pem: "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----"
                    .to_string(),
                bandwidth_limit_mbps: Some(200),
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
# Missing public_key_pem
"#;
        let file = create_temp_file(content);
        let result = UsersConfig::load(file.path());
        assert!(result.is_err());
    }
}
