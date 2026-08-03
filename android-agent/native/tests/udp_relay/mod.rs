use std::net::SocketAddr;
use std::time::{Duration, Instant};

use android_agent::netstack::{
    UdpRelayRequest, UdpRelayState, UdpRelayStats, send_udp_relay_request_batch,
};
use protocol::{Address, UdpRelayPacket};
use tokio::io::AsyncReadExt;

#[test]
fn assigns_stable_flow_ids() {
    let mut state = UdpRelayState::new();
    let client: SocketAddr = "10.10.10.2:10000".parse().unwrap();
    let target: SocketAddr = "8.8.8.8:443".parse().unwrap();

    let first = state.flow_id(client, target);
    let second = state.flow_id(client, target);

    assert_eq!(first, second);
    assert_eq!(state.flow(first).unwrap().client, client);
    assert_eq!(state.flow(first).unwrap().target, target);
}

#[test]
fn downstream_traffic_keeps_flow_mapping_alive() {
    let mut state = UdpRelayState::new();
    let client: SocketAddr = "10.10.10.2:10000".parse().unwrap();
    let target: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let flow_id = state.flow_id(client, target);
    let response_at = Instant::now() + Duration::from_secs(299);

    assert!(state.flow_at(flow_id, response_at).is_some());
    state.cleanup_expired_at(response_at + Duration::from_secs(299));
    assert!(
        state
            .flow_at(flow_id, response_at + Duration::from_secs(299))
            .is_some()
    );
}

#[tokio::test]
async fn encodes_quic_target_for_udp_relay() {
    let mut state = UdpRelayState::new();
    let client: SocketAddr = "10.10.10.2:10000".parse().unwrap();
    let target: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let address = Address::Ipv4 {
        addr: [8, 8, 8, 8],
        port: 443,
    };
    let request = UdpRelayRequest {
        client,
        target,
        address: address.clone(),
        packet: b"quic-client-initial".to_vec(),
    };
    let (mut writer, mut reader) = tokio::io::duplex(4096);

    let mut rx = tokio::sync::mpsc::channel(1).1;
    let stats = UdpRelayStats::default();
    send_udp_relay_request_batch(&mut writer, &mut state, request, &mut rx, &stats)
        .await
        .unwrap();
    drop(writer);

    let mut encoded = Vec::new();
    reader.read_to_end(&mut encoded).await.unwrap();
    let packet = UdpRelayPacket::decode(&encoded).unwrap();

    assert_eq!(packet.flow_id, 1);
    match packet.address {
        Address::Ipv4 { addr, port } => {
            assert_eq!(addr, [8, 8, 8, 8]);
            assert_eq!(port, 443);
        }
        other => panic!("unexpected relay address: {other:?}"),
    }
    assert_eq!(packet.data, b"quic-client-initial");
    assert_eq!(state.flow(packet.flow_id).unwrap().client, client);
    assert_eq!(state.flow(packet.flow_id).unwrap().target, target);

    let snapshot = stats.snapshot_and_reset();
    assert_eq!(snapshot.sent_packets, 1);
    assert_eq!(
        snapshot.sent_payload_bytes,
        b"quic-client-initial".len() as u64
    );
}
