use protocol::MessageType;
use protocol::crypto::{RsaKeyPair, encrypt_oaep_sha256_labelled, verify_pss_sha256};
use protocol::tcp_transport::{
    TCP_AUTH_NONCE_LEN, TCP_HANDSHAKE_VERSION, TCP_MASTER_SECRET_LEN, TCP_OAEP_LABEL,
    TCP_SERVER_NONCE_LEN, TCP_SESSION_ID_LEN, TCP_SESSION_SECRET_MAX_SIZE,
    TcpDirectionalKeyMaterial, TcpSessionCipher, TcpSessionRole, TcpSessionSecret,
    decode_tcp_session_secret, encode_tcp_session_secret, tcp_auth_request_transcript,
    tcp_auth_transcript_hash,
};

type CipherInputs = (
    [u8; TCP_MASTER_SECRET_LEN],
    [u8; 32],
    [u8; TCP_AUTH_NONCE_LEN],
    [u8; TCP_SERVER_NONCE_LEN],
    [u8; TCP_SESSION_ID_LEN],
);

fn cipher_inputs() -> CipherInputs {
    ([1; 32], [2; 32], [3; 32], [4; 32], [5; 16])
}

fn cipher_pair() -> (TcpSessionCipher, TcpSessionCipher) {
    let inputs = cipher_inputs();
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
fn transcript_signature_binds_every_client_context_field() {
    let key_pair = RsaKeyPair::generate(2048).unwrap();
    let public_key =
        RsaKeyPair::from_public_key_pem(&key_pair.public_key_to_pem().unwrap()).unwrap();
    let nonce = [7_u8; TCP_AUTH_NONCE_LEN];
    let transcript =
        tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 1234, &nonce).unwrap();
    let signature = key_pair.sign_pss_sha256(&transcript).unwrap();
    verify_pss_sha256(&public_key, &transcript, &signature).unwrap();

    let mut changed_nonce = nonce;
    changed_nonce[0] ^= 1;
    for changed in [
        tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "mallory", 1234, &nonce).unwrap(),
        tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 1235, &nonce).unwrap(),
        tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 1234, &changed_nonce).unwrap(),
    ] {
        assert!(verify_pss_sha256(&public_key, &changed, &signature).is_err());
    }
    assert!(tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION - 1, "alice", 1234, &nonce).is_err());
}

#[test]
fn encrypted_secret_context_rejects_replayed_response() {
    let first_nonce = [1_u8; TCP_AUTH_NONCE_LEN];
    let second_nonce = [2_u8; TCP_AUTH_NONCE_LEN];
    let first_transcript =
        tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 1, &first_nonce).unwrap();
    let second_transcript =
        tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 2, &second_nonce).unwrap();
    let secret = TcpSessionSecret {
        version: TCP_HANDSHAKE_VERSION,
        auth_transcript_hash: tcp_auth_transcript_hash(&first_transcript),
        client_nonce: first_nonce,
        server_nonce: [3; TCP_SERVER_NONCE_LEN],
        session_id: [4; TCP_SESSION_ID_LEN],
        master_secret: [5; TCP_MASTER_SECRET_LEN],
    };

    secret
        .validate_handshake_context(&tcp_auth_transcript_hash(&first_transcript), &first_nonce)
        .unwrap();
    assert!(
        secret
            .validate_handshake_context(
                &tcp_auth_transcript_hash(&second_transcript),
                &second_nonce,
            )
            .is_err()
    );
}

#[test]
fn session_secret_encoding_is_bounded_and_versioned() {
    let secret = TcpSessionSecret {
        version: TCP_HANDSHAKE_VERSION,
        auth_transcript_hash: [1; 32],
        client_nonce: [2; TCP_AUTH_NONCE_LEN],
        server_nonce: [3; TCP_SERVER_NONCE_LEN],
        session_id: [4; TCP_SESSION_ID_LEN],
        master_secret: [5; TCP_MASTER_SECRET_LEN],
    };
    let encoded = encode_tcp_session_secret(&secret).unwrap();
    let decoded = decode_tcp_session_secret(&encoded).unwrap();
    decoded
        .validate_handshake_context(&secret.auth_transcript_hash, &secret.client_nonce)
        .unwrap();

    let mut wrong_version = secret;
    wrong_version.version -= 1;
    assert!(encode_tcp_session_secret(&wrong_version).is_err());
    assert!(decode_tcp_session_secret(&vec![0; TCP_SESSION_SECRET_MAX_SIZE + 1]).is_err());
}

#[test]
fn user_authenticated_handshake_and_directional_records_interoperate() {
    let user = RsaKeyPair::generate(2048).unwrap();
    let user_public = RsaKeyPair::from_public_key_pem(&user.public_key_to_pem().unwrap()).unwrap();
    let client_nonce = [11; TCP_AUTH_NONCE_LEN];
    let request =
        tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 1_700_000_000, &client_nonce)
            .unwrap();
    let request_hash = tcp_auth_transcript_hash(&request);
    let client_proof = user.sign_pss_sha256(&request).unwrap();
    verify_pss_sha256(&user_public, &request, &client_proof).unwrap();

    let secret = TcpSessionSecret {
        version: TCP_HANDSHAKE_VERSION,
        auth_transcript_hash: request_hash,
        client_nonce,
        server_nonce: [12; TCP_SERVER_NONCE_LEN],
        session_id: [13; TCP_SESSION_ID_LEN],
        master_secret: [14; TCP_MASTER_SECRET_LEN],
    };
    let encoded_secret = encode_tcp_session_secret(&secret).unwrap();
    let encrypted_session =
        encrypt_oaep_sha256_labelled(&user_public, TCP_OAEP_LABEL, &encoded_secret).unwrap();
    let decrypted = user
        .decrypt_oaep_sha256_labelled(TCP_OAEP_LABEL, &encrypted_session)
        .unwrap();
    let accepted = decode_tcp_session_secret(&decrypted).unwrap();
    accepted
        .validate_handshake_context(&request_hash, &client_nonce)
        .unwrap();

    let agent = TcpSessionCipher::new(
        TcpSessionRole::Agent,
        accepted.master_secret,
        request_hash,
        client_nonce,
        accepted.server_nonce,
        accepted.session_id,
    )
    .unwrap();
    let proxy = TcpSessionCipher::new(
        TcpSessionRole::Proxy,
        secret.master_secret,
        request_hash,
        client_nonce,
        secret.server_nonce,
        secret.session_id,
    )
    .unwrap();
    let request_frame = agent.seal(MessageType::Data, 0, b"hello proxy").unwrap();
    assert_eq!(
        proxy
            .open(MessageType::Data, 0, request_frame.0, &request_frame.1)
            .unwrap(),
        b"hello proxy"
    );
    let response_frame = proxy.seal(MessageType::Data, 0, b"hello agent").unwrap();
    assert_eq!(
        agent
            .open(MessageType::Data, 0, response_frame.0, &response_frame.1)
            .unwrap(),
        b"hello agent"
    );
}

#[test]
fn legacy_raw_style_user_proof_is_rejected() {
    let user = RsaKeyPair::generate(2048).unwrap();
    let user_public = RsaKeyPair::from_public_key_pem(&user.public_key_to_pem().unwrap()).unwrap();
    let request =
        tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 10, &[3; TCP_AUTH_NONCE_LEN])
            .unwrap();
    let legacy_raw_style_proof = vec![0x42; user.modulus_size()];
    assert!(verify_pss_sha256(&user_public, &request, &legacy_raw_style_proof).is_err());
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
    let inputs = cipher_inputs();
    let material =
        TcpDirectionalKeyMaterial::derive(&inputs.0, &inputs.1, &inputs.2, &inputs.3, &inputs.4)
            .unwrap();
    let agent = TcpSessionCipher::from_key_material_with_sequences(
        TcpSessionRole::Agent,
        material.clone(),
        u64::MAX,
        u64::MAX,
    );
    let proxy = TcpSessionCipher::from_key_material_with_sequences(
        TcpSessionRole::Proxy,
        material,
        u64::MAX,
        u64::MAX,
    );

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
