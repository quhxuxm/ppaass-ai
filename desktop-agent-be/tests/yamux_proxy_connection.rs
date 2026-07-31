use common::ClientConnectionConfig;
use desktop_agent_be::config::AgentConfig;
use desktop_agent_be::yamux_session::proxy_connection::AgentClientConfig;
use protocol::CompressionMode;

const MINIMAL_AGENT_CONFIG: &str = r#"
listen_addr = "0.0.0.0:10080"
username = "user1"
private_key_path = "keys/user1.pem"
compression_mode = "gzip"
"#;

#[test]
fn connection_config_adapter_forwards_compression_mode() {
    let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();
    let proxy_addrs = vec!["127.0.0.1:8080".to_string()];
    let adapter = AgentClientConfig::new(&config, &proxy_addrs, None, None);

    assert_eq!(adapter.compression_mode(), CompressionMode::Gzip);
}
