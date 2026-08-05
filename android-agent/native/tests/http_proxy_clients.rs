use std::net::SocketAddr;

use android_agent::{http_proxy_clients_json, register_http_proxy_client};

#[test]
fn dropped_clients_remain_visible_as_recent_clients() {
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();
    let lease = register_http_proxy_client(peer_addr);
    let active_state = http_proxy_clients_json();
    assert!(active_state.contains("\"203.0.113.10\""));
    assert!(active_state.contains("\"active\""));

    drop(lease);

    let recent_state = http_proxy_clients_json();
    assert!(recent_state.contains("\"recent\""));
    assert!(recent_state.contains("\"203.0.113.10\""));
    assert!(recent_state.contains("\"203.0.113.10:49152\""));
}
