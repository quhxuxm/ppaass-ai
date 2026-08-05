use super::*;
use std::sync::Arc;

#[test]
fn all_session_message_variants_are_bitcode_serializable() {
    let messages = [
        UdpSessionMessage::OpenData {
            flow_id: 1,
            address: Address::Ipv4 {
                addr: [127, 0, 0, 1],
                port: 53,
            },
            data: vec![0, 1, 2],
        },
        UdpSessionMessage::ConnectResponse {
            flow_id: 1,
            success: true,
            error: None,
        },
        UdpSessionMessage::Data {
            flow_id: 1,
            data: vec![1, 2, 3],
        },
        UdpSessionMessage::Close {
            flow_id: 1,
            reason: Some("done".to_owned()),
        },
        UdpSessionMessage::Ping { token: 2 },
        UdpSessionMessage::Pong { token: 2 },
    ];

    for (expected_index, message) in messages.iter().enumerate() {
        let decoded = UdpSessionMessage::decode(&message.encode().unwrap()).unwrap();
        let actual_index = match decoded {
            UdpSessionMessage::OpenData { .. } => 0,
            UdpSessionMessage::ConnectResponse { .. } => 1,
            UdpSessionMessage::Data { .. } => 2,
            UdpSessionMessage::Close { .. } => 3,
            UdpSessionMessage::Ping { .. } => 4,
            UdpSessionMessage::Pong { .. } => 5,
        };
        assert_eq!(actual_index, expected_index);
    }
}

#[test]
fn borrowed_udp_relay_encoding_matches_owned_encoding() {
    let packet = UdpRelayPacket {
        flow_id: 42,
        address: Address::Domain {
            host: "relay.example".to_string(),
            port: 443,
        },
        data: vec![1, 3, 3, 7],
    };

    let borrowed = UdpRelayPacket::encode_parts(packet.flow_id, &packet.address, &packet.data)
        .expect("borrowed packet should encode");
    assert_eq!(
        borrowed,
        packet.encode().expect("owned packet should encode")
    );
    assert_eq!(UdpRelayPacket::decode(&borrowed).unwrap().data, packet.data);
}

#[test]
fn parsed_public_key_is_reused_for_identical_pem() {
    let generated = RsaKeyPair::generate(2048).unwrap();
    let pem = generated.public_key_to_pem().unwrap();

    let first = protocol::crypto::parse_public_key_pem_cached(&pem).unwrap();
    let second = protocol::crypto::parse_public_key_pem_cached(&pem).unwrap();

    assert!(Arc::ptr_eq(&first, &second));
}
