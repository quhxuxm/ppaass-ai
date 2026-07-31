use desktop_agent_be::config::AgentConfig;
use desktop_agent_be::tun_handler::proxy_routing::ProxySessionBindGuard;
use desktop_agent_be::yamux_session::YamuxSessionManager;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const MINIMAL_AGENT_CONFIG: &str = r#"
listen_addr = "127.0.0.1:10080"
username = "user1"
private_key_path = "keys/user1.pem"
"#;

#[test]
fn proxy_session_bind_guard_clears_both_shared_managers_on_drop() {
    let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();
    let config = Arc::new(config);
    let proxy_addrs = Arc::new(vec!["127.0.0.1:8080".to_string()]);
    let tcp_sessions = Arc::new(YamuxSessionManager::new(
        config.clone(),
        proxy_addrs.clone(),
    ));
    let udp_sessions = Arc::new(YamuxSessionManager::new_udp(config, proxy_addrs));
    let bind_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let bind_interface = common::BindInterface {
        name: Some("physical0".to_string()),
        index: Some(7),
    };

    {
        let _guard = ProxySessionBindGuard::new(tcp_sessions.clone(), udp_sessions.clone());
        tcp_sessions.set_proxy_bind_ip(Some(bind_ip));
        tcp_sessions.set_proxy_bind_interface(Some(bind_interface.clone()));
        udp_sessions.set_proxy_bind_ip(Some(bind_ip));
        udp_sessions.set_proxy_bind_interface(Some(bind_interface.clone()));

        assert_eq!(tcp_sessions.proxy_bind_ip(), Some(bind_ip));
        assert_eq!(
            tcp_sessions.proxy_bind_interface(),
            Some(bind_interface.clone())
        );
        assert_eq!(udp_sessions.proxy_bind_ip(), Some(bind_ip));
        assert_eq!(udp_sessions.proxy_bind_interface(), Some(bind_interface));
    }

    assert_eq!(tcp_sessions.proxy_bind_ip(), None);
    assert_eq!(tcp_sessions.proxy_bind_interface(), None);
    assert_eq!(udp_sessions.proxy_bind_ip(), None);
    assert_eq!(udp_sessions.proxy_bind_interface(), None);
}
