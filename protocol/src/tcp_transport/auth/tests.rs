use super::*;
use crate::MessageType;
use crate::crypto::{RsaKeyPair, encrypt_oaep_sha256_labelled, verify_pss_sha256};
use crate::tcp_transport::{TcpSessionCipher, TcpSessionRole};

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
fn proxy_signature_binds_version_request_and_complete_ciphertext() {
    let proxy_identity = RsaKeyPair::generate(2048).unwrap();
    let proxy_public =
        RsaKeyPair::from_public_key_pem(&proxy_identity.public_key_to_pem().unwrap()).unwrap();
    let request_hash = [7_u8; 32];
    let ciphertext = vec![9_u8; 256];
    let transcript =
        tcp_auth_response_signature_transcript(TCP_HANDSHAKE_VERSION, &request_hash, &ciphertext)
            .unwrap();
    let signature = proxy_identity.sign_pss_sha256(&transcript).unwrap();
    verify_pss_sha256(&proxy_public, &transcript, &signature).unwrap();

    let mut changed_hash = request_hash;
    changed_hash[0] ^= 1;
    let changed_request =
        tcp_auth_response_signature_transcript(TCP_HANDSHAKE_VERSION, &changed_hash, &ciphertext)
            .unwrap();
    assert!(verify_pss_sha256(&proxy_public, &changed_request, &signature).is_err());

    let mut changed_ciphertext = ciphertext;
    changed_ciphertext[31] ^= 1;
    let changed_response = tcp_auth_response_signature_transcript(
        TCP_HANDSHAKE_VERSION,
        &request_hash,
        &changed_ciphertext,
    )
    .unwrap();
    assert!(verify_pss_sha256(&proxy_public, &changed_response, &signature).is_err());
}

#[test]
fn failure_signature_binds_request_code_and_message() {
    let proxy_identity = RsaKeyPair::generate(2048).unwrap();
    let proxy_public =
        RsaKeyPair::from_public_key_pem(&proxy_identity.public_key_to_pem().unwrap()).unwrap();
    let request_hash = [21_u8; 32];
    let transcript = tcp_auth_failure_signature_transcript(
        TCP_HANDSHAKE_VERSION,
        &request_hash,
        AuthFailureCode::UserExpired,
        "User expired",
    )
    .unwrap();
    let signature = proxy_identity.sign_pss_sha256(&transcript).unwrap();
    verify_pss_sha256(&proxy_public, &transcript, &signature).unwrap();

    let mut changed_hash = request_hash;
    changed_hash[0] ^= 1;
    for changed in [
        tcp_auth_failure_signature_transcript(
            TCP_HANDSHAKE_VERSION,
            &changed_hash,
            AuthFailureCode::UserExpired,
            "User expired",
        )
        .unwrap(),
        tcp_auth_failure_signature_transcript(
            TCP_HANDSHAKE_VERSION,
            &request_hash,
            AuthFailureCode::UserDisabled,
            "User expired",
        )
        .unwrap(),
        tcp_auth_failure_signature_transcript(
            TCP_HANDSHAKE_VERSION,
            &request_hash,
            AuthFailureCode::UserExpired,
            "User expired today",
        )
        .unwrap(),
    ] {
        assert!(verify_pss_sha256(&proxy_public, &changed, &signature).is_err());
    }
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
fn complete_signed_handshake_and_directional_records_interoperate() {
    let user = RsaKeyPair::generate(2048).unwrap();
    let user_public = RsaKeyPair::from_public_key_pem(&user.public_key_to_pem().unwrap()).unwrap();
    let proxy_identity = RsaKeyPair::generate(2048).unwrap();
    let pinned_proxy_public =
        RsaKeyPair::from_public_key_pem(&proxy_identity.public_key_to_pem().unwrap()).unwrap();
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
    let response_transcript = tcp_auth_response_signature_transcript(
        TCP_HANDSHAKE_VERSION,
        &request_hash,
        &encrypted_session,
    )
    .unwrap();
    let proxy_signature = proxy_identity
        .sign_pss_sha256(&response_transcript)
        .unwrap();

    // Client verifies the pinned server identity before OAEP decryption.
    verify_pss_sha256(&pinned_proxy_public, &response_transcript, &proxy_signature).unwrap();
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
            .open(MessageType::Data, 0, request_frame.0, &request_frame.1,)
            .unwrap(),
        b"hello proxy"
    );
    let response_frame = proxy.seal(MessageType::Data, 0, b"hello agent").unwrap();
    assert_eq!(
        agent
            .open(MessageType::Data, 0, response_frame.0, &response_frame.1,)
            .unwrap(),
        b"hello agent"
    );
}

#[test]
fn wrong_proxy_pin_and_legacy_raw_style_proof_are_rejected() {
    let user = RsaKeyPair::generate(2048).unwrap();
    let user_public = RsaKeyPair::from_public_key_pem(&user.public_key_to_pem().unwrap()).unwrap();
    let proxy_identity = RsaKeyPair::generate(2048).unwrap();
    let wrong_proxy_identity = RsaKeyPair::generate(2048).unwrap();
    let wrong_pin =
        RsaKeyPair::from_public_key_pem(&wrong_proxy_identity.public_key_to_pem().unwrap())
            .unwrap();
    let request_hash = [1; 32];
    let ciphertext = vec![2; user.modulus_size()];
    let response_transcript =
        tcp_auth_response_signature_transcript(TCP_HANDSHAKE_VERSION, &request_hash, &ciphertext)
            .unwrap();
    let proxy_signature = proxy_identity
        .sign_pss_sha256(&response_transcript)
        .unwrap();
    assert!(verify_pss_sha256(&wrong_pin, &response_transcript, &proxy_signature).is_err());

    let request =
        tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 10, &[3; TCP_AUTH_NONCE_LEN])
            .unwrap();
    // The retired wire path sent a modulus-sized raw private-RSA result,
    // not a PSS signature. A modulus-sized opaque blob must not pass.
    let legacy_raw_style_proof = vec![0x42; user.modulus_size()];
    assert!(verify_pss_sha256(&user_public, &request, &legacy_raw_style_proof).is_err());
}
