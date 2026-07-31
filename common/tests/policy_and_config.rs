use common::dns::{DnsQuery, is_dns_query_packet, parse_dns_query_packet};
use common::quic::{QuicPolicy, QuicUdpStats, QuicUdpStatsSnapshot};
use common::transport::TransportMode;
use common::tun_control::{tun_helper_dns_state_path, tun_helper_route_state_path};
use common::yamux_settings::{
    DEFAULT_YAMUX_MAX_STREAMS_PER_SESSION, DEFAULT_YAMUX_SERVER_CONNECTION_WRITE_TIMEOUT_SECS,
    DEFAULT_YAMUX_SERVER_MAX_STREAMS_PER_SESSION, DEFAULT_YAMUX_SERVER_STREAM_WINDOW_SIZE_KB,
    YamuxConfig, YamuxServerConfig,
};
use protocol::TransportProtocol;
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

#[test]
fn quic_policy_only_blocks_when_policy_is_block() {
    assert!(!QuicPolicy::Allow.should_block_udp443());
    assert!(QuicPolicy::Block.should_block_udp443());
}

#[test]
fn quic_policy_uses_snake_case_config_values() {
    #[derive(Deserialize)]
    struct PolicyWrapper {
        value: QuicPolicy,
    }

    let policy = toml::from_str::<PolicyWrapper>("value = \"block\"")
        .unwrap()
        .value;
    assert_eq!(policy, QuicPolicy::Block);
}

#[test]
fn quic_stats_snapshot_resets_counters() {
    let stats = QuicUdpStats::default();
    stats.record_direct();
    stats.record_proxied();
    stats.record_blocked();

    assert_eq!(
        stats.snapshot_and_reset(),
        QuicUdpStatsSnapshot {
            observed: 3,
            direct: 1,
            proxied: 1,
            blocked: 1,
        }
    );
    assert_eq!(stats.snapshot_and_reset(), QuicUdpStatsSnapshot::default());
}

#[test]
fn parses_standard_dns_query() {
    assert_eq!(
        parse_dns_query_packet(&example_query()),
        Some(DnsQuery {
            query: "example.com".to_string(),
            record_type: "A".to_string(),
        })
    );
}

#[test]
fn rejects_dns_response_as_query() {
    let mut packet = example_query();
    packet[2] = 0x81;
    packet[3] = 0x80;

    assert_eq!(parse_dns_query_packet(&packet), None);
    assert!(!is_dns_query_packet(&packet));
}

#[test]
fn rejects_query_with_multiple_questions() {
    let mut packet = example_query();
    packet[5] = 0x02;
    packet.extend_from_slice(&[
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'n', b'e', b't', 0x00, 0x00, 0x1c,
        0x00, 0x01,
    ]);

    assert_eq!(parse_dns_query_packet(&packet), None);
}

#[test]
fn rejects_query_with_trailing_bytes() {
    let mut packet = example_query();
    packet.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    assert_eq!(parse_dns_query_packet(&packet), None);
}

#[test]
fn transport_mode_defaults_to_udp_and_parses_tcp() {
    #[derive(Deserialize)]
    struct Wrapper {
        mode: TransportMode,
    }

    assert_eq!(TransportMode::default(), TransportMode::Udp);
    assert_eq!(
        toml::from_str::<Wrapper>("mode = \"tcp\"").unwrap().mode,
        TransportMode::Tcp
    );
    assert_eq!(
        toml::from_str::<Wrapper>("mode = \"auto\"").unwrap().mode,
        TransportMode::Auto
    );
}

#[test]
fn udp_mode_never_routes_tcp_over_udp() {
    assert!(!TransportMode::Udp.uses_native_udp_for(TransportProtocol::Tcp));
    assert!(TransportMode::Udp.uses_native_udp_for(TransportProtocol::Udp));
    assert!(!TransportMode::Tcp.uses_native_udp_for(TransportProtocol::Tcp));
    assert!(!TransportMode::Tcp.uses_native_udp_for(TransportProtocol::Udp));
    assert!(TransportMode::Auto.uses_native_udp_for(TransportProtocol::Udp));
    assert!(TransportMode::Auto.automatically_falls_back_to_tcp());
}

#[test]
fn rejects_removed_quic_transport_mode() {
    #[derive(Deserialize)]
    struct Wrapper {
        #[allow(dead_code)]
        mode: TransportMode,
    }

    assert!(toml::from_str::<Wrapper>("mode = \"quic\"").is_err());
}

#[test]
fn helper_state_files_are_scoped_to_the_socket_directory() {
    let socket = Path::new("/var/run/ppaass-ai/custom-helper.sock");
    assert_eq!(
        tun_helper_route_state_path(socket),
        Path::new("/var/run/ppaass-ai/tun-routes.json")
    );
    assert_eq!(
        tun_helper_dns_state_path(socket),
        Path::new("/var/run/ppaass-ai/tun-dns.json")
    );
}

#[test]
fn parses_udp_only_yamux_config() {
    let config: YamuxConfig = toml::from_str(
        r#"
[udp]
sessions = 3
max_streams_per_session = 32
open_stream_timeout_secs = 5
keepalive_interval_secs = 0
connection_write_timeout_secs = 9
stream_window_size_kb = 1024
"#,
    )
    .unwrap();

    assert_eq!(config.udp_session_count(), 3);
    let udp = config.udp_settings();
    assert_eq!(udp.max_streams_per_session, 32);
    assert_eq!(udp.open_stream_timeout, Duration::from_secs(5));
    assert_eq!(udp.keepalive_interval, None);
    assert_eq!(udp.connection_write_timeout, Duration::from_secs(9));
    assert_eq!(udp.stream_window_size_kb, 1024);
}

#[test]
fn client_yamux_defaults_limit_single_session_fanout() {
    let udp = YamuxConfig::default().udp_settings();
    assert_eq!(
        udp.max_streams_per_session,
        DEFAULT_YAMUX_MAX_STREAMS_PER_SESSION
    );
    assert_eq!(DEFAULT_YAMUX_MAX_STREAMS_PER_SESSION, 32);
}

#[test]
fn rejects_agent_tcp_yamux_config() {
    let error = toml::from_str::<YamuxConfig>(
        r#"
[tcp]
sessions = 5
max_streams_per_session = 32
"#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn rejects_legacy_flat_agent_yamux_config() {
    let error = toml::from_str::<YamuxConfig>(
        r#"
sessions = 5
max_streams_per_session = 32
"#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn rejects_server_yamux_sessions_config() {
    let error = toml::from_str::<YamuxServerConfig>(
        r#"
sessions = 5
max_streams_per_session = 32
"#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn rejects_server_yamux_open_stream_timeout_config() {
    let error = toml::from_str::<YamuxServerConfig>(
        r#"
open_stream_timeout_secs = 10
max_streams_per_session = 32
"#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn server_yamux_defaults_are_acceptor_friendly() {
    let settings = YamuxServerConfig::default().settings();
    assert_eq!(
        settings.max_streams_per_session,
        DEFAULT_YAMUX_SERVER_MAX_STREAMS_PER_SESSION
    );
    assert_eq!(
        settings.connection_write_timeout,
        Duration::from_secs(DEFAULT_YAMUX_SERVER_CONNECTION_WRITE_TIMEOUT_SECS)
    );
    assert_eq!(
        settings.stream_window_size_kb,
        DEFAULT_YAMUX_SERVER_STREAM_WINDOW_SIZE_KB
    );
}

fn example_query() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'E', b'x',
        b'A', b'm', b'P', b'l', b'E', 0x03, b'c', b'O', b'M', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]
}
