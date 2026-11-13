mod support;

use protocol::Address;
use protocol::udp_transport::{UdpSessionCodec, UdpSessionMessage, UdpSessionRole};
use proxy_entry::access_log::AccessRecorder;
use proxy_entry::config::UserConfig;
use proxy_entry::connection::EgressState;
use proxy_entry::native_udp::session::{SessionContext, run_session};
use proxy_entry::user_manager::UserManager;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

#[tokio::test]
async fn consecutive_new_channels_all_forward_their_first_datagram() {
    let user = UserConfig {
        username: "alice".into(),
        public_key_pem: "session-key".into(),
        expires_at: None,
        permissions: vec!["proxy.connect.udp".into()],
        enabled: true,
        key_version: Some(1),
    };
    let manager = Arc::new(UserManager::new(Arc::new(
        support::TestAuthorizationProvider::new([user]),
    )));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_address = Address::Ipv4 {
        addr: [127, 0, 0, 1],
        port: target.local_addr().unwrap().port(),
    };
    let context = SessionContext {
        socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        config: Arc::new(support::proxy_config("udp_session_max_flows = 128")),
        user_manager: manager,
        egress_state: Arc::new(EgressState::new(None, None).unwrap()),
        access_recorder: AccessRecorder::default(),
        username: "alice".into(),
        authenticated_public_key_pem: "session-key".into(),
        authenticated_key_version: Some(1),
        expires_at: None,
        peer: client.local_addr().unwrap(),
    };
    let codec = |role| UdpSessionCodec::new(role, [1; 16], [2; 32], [3; 32], [4; 32]).unwrap();
    let mut client_codec = codec(UdpSessionRole::Agent);
    let (input, incoming) = mpsc::channel(128);
    for flow_id in 0..128_u64 {
        let message = UdpSessionMessage::OpenData {
            flow_id,
            address: target_address.clone(),
            data: flow_id.to_be_bytes().to_vec(),
        };
        for datagram in client_codec.encode_message(&message).unwrap() {
            input.send(datagram).await.unwrap();
        }
    }
    let session = tokio::spawn(run_session(context, codec(UdpSessionRole::Proxy), incoming));
    let echo = tokio::spawn(async move {
        let mut data = [0; 8];
        for _ in 0..128 {
            let (size, peer) = target.recv_from(&mut data).await.unwrap();
            assert_eq!(size, 8);
            target.send_to(&data[..size], peer).await.unwrap();
        }
    });
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut connected = HashSet::new();
        let mut received = HashSet::new();
        let mut datagram = [0; 2048];
        while connected.len() < 128 || received.len() < 128 {
            let size = client.recv(&mut datagram).await.unwrap();
            match client_codec.decode_datagram(&datagram[..size]).unwrap() {
                Some(UdpSessionMessage::ConnectResponse {
                    flow_id,
                    success,
                    error,
                }) => {
                    assert!(success, "flow {flow_id} failed: {error:?}");
                    assert!(connected.insert(flow_id));
                }
                Some(UdpSessionMessage::Data { flow_id, data }) => {
                    assert_eq!(data, flow_id.to_be_bytes());
                    assert!(received.insert(flow_id));
                }
                other => panic!("unexpected session message: {other:?}"),
            }
        }
    })
    .await;
    drop(input);
    session.abort();
    echo.abort();
    result.expect("all 128 new channels must connect and return target responses");
}
