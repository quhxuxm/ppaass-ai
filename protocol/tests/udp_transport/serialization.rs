use super::*;

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
