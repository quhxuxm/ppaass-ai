use super::*;

#[test]
fn auth_datagrams_share_header_and_validate_kind_and_size() {
    let init = UdpAuthInit {
        username: "alice".to_owned(),
        timestamp: 1_700_000_000,
        client_nonce: CLIENT_NONCE,
        proof: vec![7; 256],
    };
    let encoded = encode_auth_init(SESSION_ID, &init).unwrap();
    assert!(encoded.len() <= UDP_MAX_DATAGRAM_SIZE);
    let (header, decoded) = decode_auth_init(&encoded).unwrap();
    assert_eq!(header.kind, UdpPacketKind::AuthInit);
    assert_eq!(header.session_id, SESSION_ID);
    assert_eq!(decoded.username, init.username);
    assert_eq!(decoded.client_nonce, CLIENT_NONCE);
    assert_eq!(decoded.proof, init.proof);
    assert!(matches!(
        decode_auth_ok(&encoded),
        Err(UdpTransportError::UnexpectedPacketKind { .. })
    ));

    let ok = UdpAuthOk {
        encrypted_session_secret: vec![9; 256],
        proxy_signature: vec![10; 256],
    };
    let encoded_ok = encode_auth_ok(SESSION_ID, &ok).unwrap();
    let (ok_header, decoded_ok) = decode_auth_ok(&encoded_ok).unwrap();
    assert_eq!(ok_header.kind, UdpPacketKind::AuthOk);
    assert_eq!(ok_header.session_id, SESSION_ID);
    assert_eq!(
        decoded_ok.encrypted_session_secret,
        ok.encrypted_session_secret
    );
    assert_eq!(decoded_ok.proxy_signature, ok.proxy_signature);

    let oversized = UdpAuthInit {
        proof: noisy_bytes(UDP_MAX_DATAGRAM_SIZE * 2),
        ..init
    };
    assert!(matches!(
        encode_auth_init(SESSION_ID, &oversized),
        Err(UdpTransportError::DatagramTooLarge(_))
    ));
}

#[test]
fn auth_magic_version_and_payload_length_are_checked() {
    let init = UdpAuthInit {
        username: "alice".to_owned(),
        timestamp: 42,
        client_nonce: CLIENT_NONCE,
        proof: vec![1, 2, 3],
    };
    let encoded = encode_auth_init(SESSION_ID, &init).unwrap();

    let mut bad_magic = encoded.clone();
    bad_magic[0] ^= 0xff;
    assert!(matches!(
        decode_auth_init(&bad_magic),
        Err(UdpTransportError::InvalidMagic)
    ));

    let mut bad_version = encoded.clone();
    bad_version[4] = UDP_TRANSPORT_VERSION + 1;
    assert!(matches!(
        decode_auth_init(&bad_version),
        Err(UdpTransportError::UnsupportedVersion(version))
            if version == UDP_TRANSPORT_VERSION + 1
    ));

    let mut truncated = encoded;
    truncated.pop();
    assert!(matches!(
        decode_auth_init(&truncated),
        Err(UdpTransportError::InvalidHeader(_))
    ));
}

#[test]
fn session_secret_roundtrips_and_auth_transcript_binds_every_input() {
    let secret = UdpSessionSecret {
        version: UDP_TRANSPORT_VERSION,
        session_id: SESSION_ID,
        client_nonce: CLIENT_NONCE,
        master_key: MASTER_KEY,
        server_nonce: SERVER_NONCE,
    };
    let decoded = decode_session_secret(&encode_session_secret(&secret).unwrap()).unwrap();
    assert_eq!(decoded.session_id, SESSION_ID);
    assert_eq!(decoded.client_nonce, CLIENT_NONCE);
    assert_eq!(decoded.master_key, MASTER_KEY);
    assert_eq!(decoded.server_nonce, SERVER_NONCE);
    decoded
        .validate_handshake_context(&SESSION_ID, &CLIENT_NONCE)
        .unwrap();
    assert!(
        decoded
            .validate_handshake_context(&[0x12; 16], &CLIENT_NONCE)
            .is_err()
    );
    assert!(
        decoded
            .validate_handshake_context(&SESSION_ID, &[0x34; 32])
            .is_err()
    );

    let digest = udp_auth_proof_digest(&SESSION_ID, "alice", 100, &CLIENT_NONCE);
    assert_ne!(
        digest,
        udp_auth_proof_digest(&[0x12; 16], "alice", 100, &CLIENT_NONCE)
    );
    assert_ne!(
        digest,
        udp_auth_proof_digest(&SESSION_ID, "bob", 100, &CLIENT_NONCE)
    );
    assert_ne!(
        digest,
        udp_auth_proof_digest(&SESSION_ID, "alice", 101, &CLIENT_NONCE)
    );
    assert_ne!(
        digest,
        udp_auth_proof_digest(&SESSION_ID, "alice", 100, &[0x34; 32])
    );
}

#[test]
fn encrypted_session_secret_is_bound_to_one_handshake_context() {
    let pair = RsaKeyPair::generate(2048).unwrap();
    let public_key = RsaKeyPair::from_public_key_pem(&pair.public_key_to_pem().unwrap()).unwrap();
    let secret = UdpSessionSecret {
        version: UDP_TRANSPORT_VERSION,
        session_id: SESSION_ID,
        client_nonce: CLIENT_NONCE,
        master_key: MASTER_KEY,
        server_nonce: SERVER_NONCE,
    };
    let plaintext = encode_session_secret(&secret).unwrap();
    let ciphertext = encrypt_oaep_sha256_labelled(&public_key, UDP_OAEP_LABEL, &plaintext).unwrap();
    let decoded = decode_session_secret(
        &pair
            .decrypt_oaep_sha256_labelled(UDP_OAEP_LABEL, &ciphertext)
            .unwrap(),
    )
    .unwrap();

    decoded
        .validate_handshake_context(&SESSION_ID, &CLIENT_NONCE)
        .unwrap();
    assert!(
        decoded
            .validate_handshake_context(&[0x12; 16], &CLIENT_NONCE)
            .is_err()
    );
    assert!(
        decoded
            .validate_handshake_context(&SESSION_ID, &[0x34; 32])
            .is_err()
    );
}

#[test]
fn signed_auth_ok_binds_request_ciphertext_and_rejects_replay_to_new_context() {
    let proxy_identity = RsaKeyPair::generate(2048).unwrap();
    let pinned_proxy_public =
        RsaKeyPair::from_public_key_pem(&proxy_identity.public_key_to_pem().unwrap()).unwrap();
    let wrong_proxy_identity = RsaKeyPair::generate(2048).unwrap();
    let wrong_pin =
        RsaKeyPair::from_public_key_pem(&wrong_proxy_identity.public_key_to_pem().unwrap())
            .unwrap();
    let proof_digest = udp_auth_proof_digest(&SESSION_ID, "alice", 100, &CLIENT_NONCE);
    let ciphertext = vec![0x55; 256];
    let transcript =
        udp_auth_ok_signature_transcript(&SESSION_ID, &proof_digest, &ciphertext).unwrap();
    let signature = proxy_identity.sign_pss_sha256(&transcript).unwrap();
    verify_pss_sha256(&pinned_proxy_public, &transcript, &signature).unwrap();
    assert!(verify_pss_sha256(&wrong_pin, &transcript, &signature).is_err());

    let replay_session = [0x12; 16];
    let replay_digest = udp_auth_proof_digest(&replay_session, "alice", 101, &[0x34; 32]);
    let replay_transcript =
        udp_auth_ok_signature_transcript(&replay_session, &replay_digest, &ciphertext).unwrap();
    assert!(verify_pss_sha256(&pinned_proxy_public, &replay_transcript, &signature).is_err());

    let mut tampered_ciphertext = ciphertext;
    tampered_ciphertext[0] ^= 1;
    let tampered =
        udp_auth_ok_signature_transcript(&SESSION_ID, &proof_digest, &tampered_ciphertext).unwrap();
    assert!(verify_pss_sha256(&pinned_proxy_public, &tampered, &signature).is_err());
}
