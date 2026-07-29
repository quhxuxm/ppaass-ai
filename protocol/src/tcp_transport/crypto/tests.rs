use super::*;

fn cipher_pair() -> (TcpSessionCipher, TcpSessionCipher) {
    let inputs = (
        [1; TCP_MASTER_SECRET_LEN],
        [2; 32],
        [3; TCP_AUTH_NONCE_LEN],
        [4; TCP_SERVER_NONCE_LEN],
        [5; TCP_SESSION_ID_LEN],
    );
    (
        TcpSessionCipher::new(
            TcpSessionRole::Agent,
            inputs.0,
            inputs.1,
            inputs.2,
            inputs.3,
            inputs.4,
        )
        .unwrap(),
        TcpSessionCipher::new(
            TcpSessionRole::Proxy,
            inputs.0,
            inputs.1,
            inputs.2,
            inputs.3,
            inputs.4,
        )
        .unwrap(),
    )
}

#[test]
fn both_directions_interoperate_but_reflection_fails() {
    let (agent, proxy) = cipher_pair();
    let (sequence, ciphertext) = agent.seal(MessageType::Data, 0, b"request").unwrap();
    assert_eq!(
        proxy
            .open(MessageType::Data, 0, sequence, &ciphertext)
            .unwrap(),
        b"request"
    );
    assert!(
        agent
            .open(MessageType::Data, 0, sequence, &ciphertext)
            .is_err()
    );

    let (sequence, ciphertext) = proxy.seal(MessageType::Data, 0, b"response").unwrap();
    assert_eq!(
        agent
            .open(MessageType::Data, 0, sequence, &ciphertext)
            .unwrap(),
        b"response"
    );
}

#[test]
fn duplicate_skipped_and_reordered_sequences_are_rejected() {
    let (agent, proxy) = cipher_pair();
    let first = agent.seal(MessageType::Data, 0, b"first").unwrap();
    let second = agent.seal(MessageType::Data, 0, b"second").unwrap();

    assert!(
        proxy
            .open(MessageType::Data, 0, second.0, &second.1)
            .is_err()
    );
    proxy.open(MessageType::Data, 0, first.0, &first.1).unwrap();
    assert!(proxy.open(MessageType::Data, 0, first.0, &first.1).is_err());
    proxy
        .open(MessageType::Data, 0, second.0, &second.1)
        .unwrap();
}

#[test]
fn aad_binds_type_compression_and_direction() {
    let (agent, proxy) = cipher_pair();
    let frame = agent.seal(MessageType::Data, 2, b"payload").unwrap();
    assert!(
        proxy
            .open(MessageType::ConnectRequest, 2, frame.0, &frame.1)
            .is_err()
    );

    let (agent, proxy) = cipher_pair();
    let frame = agent.seal(MessageType::Data, 2, b"payload").unwrap();
    assert!(proxy.open(MessageType::Data, 3, frame.0, &frame.1).is_err());
}

#[test]
fn sequence_exhaustion_fails_closed() {
    let (agent, proxy) = cipher_pair();
    agent.send_sequence.lock().unwrap().next = u64::MAX;
    proxy.receive_sequence.lock().unwrap().next = u64::MAX;
    let final_frame = agent.seal(MessageType::Data, 0, b"last").unwrap();
    proxy
        .open(MessageType::Data, 0, final_frame.0, &final_frame.1)
        .unwrap();
    assert!(agent.seal(MessageType::Data, 0, b"too late").is_err());
    assert!(
        proxy
            .open(MessageType::Data, 0, u64::MAX, &final_frame.1)
            .is_err()
    );
}
