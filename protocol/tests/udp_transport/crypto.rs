use super::*;

#[test]
fn hkdf_separates_directions_and_binds_all_session_context() {
    let material =
        UdpDirectionalKeyMaterial::derive(&MASTER_KEY, &SESSION_ID, &CLIENT_NONCE, &SERVER_NONCE)
            .unwrap();
    assert_ne!(material.client_to_server_key, material.server_to_client_key);
    assert_ne!(
        material.client_to_server_nonce_prefix,
        material.server_to_client_nonce_prefix
    );

    let changed =
        UdpDirectionalKeyMaterial::derive(&MASTER_KEY, &SESSION_ID, &[0x35; 32], &SERVER_NONCE)
            .unwrap();
    assert_ne!(material.client_to_server_key, changed.client_to_server_key);
    assert_ne!(material.server_to_client_key, changed.server_to_client_key);
}

#[test]
fn roles_automatically_select_opposite_send_and_receive_directions() {
    let (mut agent, mut proxy) = codecs();
    let ping = UdpSessionMessage::Ping { token: 7 };
    let datagram = agent.encode_message(&ping).unwrap().pop().unwrap();
    assert!(matches!(
        proxy.decode_datagram(&datagram).unwrap(),
        Some(UdpSessionMessage::Ping { token: 7 })
    ));

    let pong = UdpSessionMessage::Pong { token: 7 };
    let datagram = proxy.encode_message(&pong).unwrap().pop().unwrap();
    assert!(matches!(
        agent.decode_datagram(&datagram).unwrap(),
        Some(UdpSessionMessage::Pong { token: 7 })
    ));
}

#[test]
fn wrong_direction_key_is_rejected() {
    let (mut sender, _) = codecs();
    let mut wrong_receiver = UdpSessionCodec::new(
        UdpSessionRole::Agent,
        SESSION_ID,
        MASTER_KEY,
        CLIENT_NONCE,
        SERVER_NONCE,
    )
    .unwrap();
    let datagram = sender
        .encode_message(&UdpSessionMessage::Ping { token: 1 })
        .unwrap()
        .pop()
        .unwrap();
    assert!(matches!(
        wrong_receiver.decode_datagram(&datagram),
        Err(UdpTransportError::AuthenticationFailed)
    ));
}

#[test]
fn header_and_ciphertext_tampering_fail_without_committing_replay_state() {
    let (mut agent, mut proxy) = codecs();
    let datagram = agent
        .encode_message(&UdpSessionMessage::Ping { token: 99 })
        .unwrap()
        .pop()
        .unwrap();

    let mut header_tampered = datagram.clone();
    header_tampered[30] ^= 1;
    assert!(matches!(
        proxy.decode_datagram(&header_tampered),
        Err(UdpTransportError::AuthenticationFailed)
    ));

    let mut ciphertext_tampered = datagram.clone();
    *ciphertext_tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        proxy.decode_datagram(&ciphertext_tampered),
        Err(UdpTransportError::AuthenticationFailed)
    ));

    assert!(matches!(
        proxy.decode_datagram(&datagram).unwrap(),
        Some(UdpSessionMessage::Ping { token: 99 })
    ));
}

#[test]
fn accepts_out_of_order_messages_and_rejects_duplicates() {
    let (mut agent, mut proxy) = codecs();
    let mut datagrams = Vec::new();
    for token in 0..3 {
        datagrams.push(
            agent
                .encode_message(&UdpSessionMessage::Ping { token })
                .unwrap()
                .pop()
                .unwrap(),
        );
    }

    for index in [2, 0, 1] {
        assert!(matches!(
            proxy.decode_datagram(&datagrams[index]).unwrap(),
            Some(UdpSessionMessage::Ping { token }) if token == index as u64
        ));
    }
    assert!(matches!(
        proxy.decode_datagram(&datagrams[1]),
        Err(UdpTransportError::ReplayRejected)
    ));
}

#[test]
fn fragmented_message_reassembles_out_of_order() {
    let (mut agent, mut proxy) = codecs();
    let data = noisy_bytes(UDP_MAX_FRAGMENT_PLAINTEXT * 3 + 17);
    let mut datagrams = agent
        .encode_message(&UdpSessionMessage::Data {
            flow_id: 19,
            data: data.clone(),
        })
        .unwrap();
    assert!(datagrams.len() >= 4);
    datagrams.reverse();

    let mut decoded = None;
    for datagram in datagrams {
        let result = proxy.decode_datagram(&datagram).unwrap();
        if result.is_some() {
            assert!(decoded.is_none());
            decoded = result;
        }
    }
    match decoded.unwrap() {
        UdpSessionMessage::Data {
            flow_id,
            data: decoded,
        } => {
            assert_eq!(flow_id, 19);
            assert_eq!(decoded, data);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}
