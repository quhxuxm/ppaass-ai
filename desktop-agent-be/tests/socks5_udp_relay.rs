use desktop_agent_be::socks5_handler::udp_relay::{
    SocksUdpRelayState, socks_udp_relay_shard_index,
};
use protocol::Address;
use std::net::SocketAddr;

fn youtube_address() -> Address {
    Address::Domain {
        host: "www.youtube.com".to_string(),
        port: 443,
    }
}

#[test]
fn structurally_equal_targets_reuse_the_same_flow() {
    let client = SocketAddr::from(([127, 0, 0, 1], 51_000));
    let mut state = SocksUdpRelayState::new();

    let first = state.flow_id(client, &youtube_address());
    let second = state.flow_id(client, &youtube_address());

    assert_eq!(first, second);
    assert_eq!(state.active_flows(), 1);
    assert_eq!(state.tracked_flow_keys(), 1);
}

#[test]
fn client_and_target_are_both_part_of_the_flow_key() {
    let first_client = SocketAddr::from(([127, 0, 0, 1], 51_000));
    let second_client = SocketAddr::from(([127, 0, 0, 1], 51_001));
    let mut state = SocksUdpRelayState::new();

    let first = state.flow_id(first_client, &youtube_address());
    let different_client = state.flow_id(second_client, &youtube_address());
    let different_target = state.flow_id(
        first_client,
        &Address::Domain {
            host: "www.youtube.com".to_string(),
            port: 8443,
        },
    );

    assert_ne!(first, different_client);
    assert_ne!(first, different_target);
    assert_eq!(state.active_flows(), 3);
    assert_eq!(state.tracked_flow_keys(), 3);
}

#[test]
fn equal_structured_targets_choose_the_same_shard() {
    let client = SocketAddr::from(([127, 0, 0, 1], 51_000));

    let first = socks_udp_relay_shard_index(client, &youtube_address(), 4);
    let second = socks_udp_relay_shard_index(client, &youtube_address(), 4);

    assert_eq!(first, second);
}
