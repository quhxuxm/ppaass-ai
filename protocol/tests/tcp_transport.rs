use protocol::MessageType;
use protocol::crypto::{RsaKeyPair, encrypt_oaep_sha256_labelled, verify_pss_sha256};
use protocol::tcp_transport::{
    TCP_AUTH_CONNECT_INTENT_NONCE_LEN, TCP_AUTH_CONNECT_OAEP_LABEL, TCP_AUTH_NONCE_LEN,
    TCP_HANDSHAKE_VERSION, TCP_MASTER_SECRET_LEN, TCP_SERVER_NONCE_LEN, TCP_SESSION_ID_LEN,
    TcpDirectionalKeyMaterial, TcpSessionCipher, TcpSessionRole, open_auth_connect_intent,
    seal_auth_connect_intent, tcp_auth_connect_intent_aad, tcp_auth_connect_request_transcript,
    tcp_auth_connect_transcript_hash,
};
use std::sync::Arc;

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
fn auth_connect_signature_and_aead_bind_all_clear_and_secret_fields() {
    let agent = RsaKeyPair::generate(2048).unwrap();
    let proxy = RsaKeyPair::generate(2048).unwrap();
    let proxy_public =
        RsaKeyPair::from_public_key_pem(&proxy.public_key_to_pem().unwrap()).unwrap();
    let client_nonce = [7; TCP_AUTH_NONCE_LEN];
    let intent_nonce = [8; TCP_AUTH_CONNECT_INTENT_NONCE_LEN];
    let secret = [9; TCP_MASTER_SECRET_LEN];
    let wrapped =
        encrypt_oaep_sha256_labelled(&proxy_public, TCP_AUTH_CONNECT_OAEP_LABEL, &secret).unwrap();
    let aad = tcp_auth_connect_intent_aad(
        TCP_HANDSHAKE_VERSION,
        "alice",
        1234,
        &client_nonce,
        &wrapped,
        &intent_nonce,
    )
    .unwrap();
    let ciphertext =
        seal_auth_connect_intent(&secret, &intent_nonce, &aad, b"target.example:443").unwrap();
    let transcript = tcp_auth_connect_request_transcript(&aad, &ciphertext).unwrap();
    let signature = agent.sign_pss_sha256(&transcript).unwrap();
    let agent_public =
        RsaKeyPair::from_public_key_pem(&agent.public_key_to_pem().unwrap()).unwrap();
    verify_pss_sha256(&agent_public, &transcript, &signature).unwrap();
    assert_eq!(
        open_auth_connect_intent(&secret, &intent_nonce, &aad, &ciphertext).unwrap(),
        b"target.example:443"
    );
    assert!(open_auth_connect_intent(&secret, &[0; 12], &aad, &ciphertext).is_err());
    assert!(verify_pss_sha256(&agent_public, b"changed", &signature).is_err());
    assert_ne!(tcp_auth_connect_transcript_hash(&transcript), [0; 32]);
}

#[test]
fn oaep_wrapped_request_secret_can_only_be_opened_by_proxy_key() {
    let proxy = RsaKeyPair::generate(2048).unwrap();
    let other = RsaKeyPair::generate(2048).unwrap();
    let public = RsaKeyPair::from_public_key_pem(&proxy.public_key_to_pem().unwrap()).unwrap();
    let secret = [3; TCP_MASTER_SECRET_LEN];
    let wrapped =
        encrypt_oaep_sha256_labelled(&public, TCP_AUTH_CONNECT_OAEP_LABEL, &secret).unwrap();
    assert_eq!(
        proxy
            .decrypt_oaep_sha256_labelled(TCP_AUTH_CONNECT_OAEP_LABEL, &wrapped)
            .unwrap(),
        secret
    );
    assert!(
        other
            .decrypt_oaep_sha256_labelled(TCP_AUTH_CONNECT_OAEP_LABEL, &wrapped)
            .is_err()
    );
}

#[test]
fn directional_records_interoperate_and_reject_reflection() {
    let (agent, proxy) = cipher_pair();
    let frame = agent.seal(MessageType::Data, 0, b"request").unwrap();
    assert_eq!(
        proxy.open(MessageType::Data, 0, frame.0, &frame.1).unwrap(),
        b"request"
    );
    assert!(agent.open(MessageType::Data, 0, frame.0, &frame.1).is_err());
}

#[test]
fn records_bind_message_type_compression_and_sequence() {
    let (agent, proxy) = cipher_pair();
    let first = agent.seal(MessageType::Data, 2, b"first").unwrap();
    let second = agent.seal(MessageType::Data, 2, b"second").unwrap();
    assert!(
        proxy
            .open(MessageType::ConnectResponse, 2, first.0, &first.1)
            .is_err()
    );
    assert!(
        proxy
            .open(MessageType::Data, 2, second.0, &second.1)
            .is_err()
    );
    proxy.open(MessageType::Data, 2, first.0, &first.1).unwrap();
    assert!(proxy.open(MessageType::Data, 2, first.0, &first.1).is_err());
}

#[test]
fn concurrent_seals_reserve_unique_sequences_without_a_mutex() {
    let (agent, _) = cipher_pair();
    let agent = Arc::new(agent);
    let mut workers = Vec::new();
    for index in 0..32_u8 {
        let agent = agent.clone();
        workers.push(std::thread::spawn(move || {
            agent.seal(MessageType::Data, 0, &[index]).unwrap().0
        }));
    }
    let mut sequences = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    sequences.sort_unstable();
    assert_eq!(sequences, (0..32).collect::<Vec<_>>());
}

#[test]
fn exhausted_sequences_fail_closed() {
    let inputs = cipher_inputs();
    let material =
        TcpDirectionalKeyMaterial::derive(&inputs.0, &inputs.1, &inputs.2, &inputs.3, &inputs.4)
            .unwrap();
    let agent = TcpSessionCipher::from_key_material_with_sequences(
        TcpSessionRole::Agent,
        material,
        u64::MAX,
        0,
    );
    agent.seal(MessageType::Data, 0, b"last").unwrap();
    assert!(agent.seal(MessageType::Data, 0, b"too late").is_err());
}
