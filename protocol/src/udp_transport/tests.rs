use std::time::{Duration, Instant};

use crate::crypto::{RsaKeyPair, encrypt_oaep_sha256};
use crate::{Address, UdpRelayPacket};

use super::*;

const SESSION_ID: UdpSessionId = [0x11; 16];
const MASTER_KEY: [u8; 32] = [0x22; 32];
const CLIENT_NONCE: [u8; 32] = [0x33; 32];
const SERVER_NONCE: [u8; 32] = [0x44; 32];

fn codecs() -> (UdpSessionCodec, UdpSessionCodec) {
    (
        UdpSessionCodec::new(
            UdpSessionRole::Agent,
            SESSION_ID,
            MASTER_KEY,
            CLIENT_NONCE,
            SERVER_NONCE,
        )
        .unwrap(),
        UdpSessionCodec::new(
            UdpSessionRole::Proxy,
            SESSION_ID,
            MASTER_KEY,
            CLIENT_NONCE,
            SERVER_NONCE,
        )
        .unwrap(),
    )
}

fn noisy_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn fragment(
    message_id: u64,
    index: u16,
    count: u16,
    total_len: u32,
    payload: &[u8],
) -> DecryptedUdpFragment {
    DecryptedUdpFragment {
        header: UdpPacketHeader::new(
            UdpPacketKind::Encrypted,
            SESSION_ID,
            u64::from(index),
            message_id,
            index,
            count,
            total_len,
        ),
        payload: payload.to_vec(),
    }
}

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
    };
    let encoded_ok = encode_auth_ok(SESSION_ID, &ok).unwrap();
    let (ok_header, decoded_ok) = decode_auth_ok(&encoded_ok).unwrap();
    assert_eq!(ok_header.kind, UdpPacketKind::AuthOk);
    assert_eq!(ok_header.session_id, SESSION_ID);
    assert_eq!(
        decoded_ok.encrypted_session_secret,
        ok.encrypted_session_secret
    );

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
        session_id: SESSION_ID,
        client_nonce: CLIENT_NONCE,
        master_key: MASTER_KEY,
        server_nonce: SERVER_NONCE,
    };
    let plaintext = encode_session_secret(&secret).unwrap();
    let ciphertext = encrypt_oaep_sha256(&public_key, &plaintext).unwrap();
    let decoded = decode_session_secret(&pair.decrypt_oaep_sha256(&ciphertext).unwrap()).unwrap();

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
    header_tampered[30] ^= 1; // message_id is authenticated as part of the fixed header.
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

    // Both failures happened before commit, so the authentic datagram is still accepted.
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

#[test]
fn max_tun_udp_payloads_fit_one_outer_datagram() {
    // An IPv4 UDP packet can carry MTU - 20-byte IP header - 8-byte UDP
    // header. IPv6 uses a 40-byte IP header. Use maximum-width flow IDs so
    // this remains true after the bitcode integer fields grow.
    for (address, payload_len) in [
        (
            Address::Ipv4 {
                addr: [192, 0, 2, 1],
                port: 443,
            },
            usize::from(UDP_NATIVE_MAX_TUN_MTU) - 20 - 8,
        ),
        (
            Address::Ipv6 {
                addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                port: 443,
            },
            usize::from(UDP_NATIVE_MAX_TUN_MTU) - 40 - 8,
        ),
    ] {
        let (mut agent, _) = codecs();
        let relay_packet = UdpRelayPacket {
            flow_id: u64::MAX,
            address,
            data: noisy_bytes(payload_len),
        }
        .encode()
        .unwrap();
        let datagrams = agent
            .encode_message(&UdpSessionMessage::Data {
                flow_id: u64::MAX,
                data: relay_packet,
            })
            .unwrap();

        assert_eq!(datagrams.len(), 1);
        assert!(datagrams[0].len() <= UDP_MAX_DATAGRAM_SIZE);
    }
}

#[test]
fn full_udp_payload_fits_70_kib_boundary_and_at_most_64_datagrams() {
    let (mut agent, mut proxy) = codecs();
    let data = vec![0xa5; 65_535];
    let message = UdpSessionMessage::Data {
        flow_id: u64::MAX,
        data: data.clone(),
    };
    let encoded_message = message.encode().unwrap();
    assert!(encoded_message.len() <= UDP_MAX_MESSAGE_SIZE);

    let datagrams = agent.encode_message(&message).unwrap();
    assert!(datagrams.len() <= UDP_MAX_FRAGMENTS);
    assert!(
        datagrams
            .iter()
            .all(|packet| packet.len() <= UDP_MAX_DATAGRAM_SIZE)
    );
    let mut decoded = None;
    for datagram in datagrams.into_iter().rev() {
        decoded = proxy.decode_datagram(&datagram).unwrap().or(decoded);
    }
    match decoded.unwrap() {
        UdpSessionMessage::Data { data: result, .. } => assert_eq!(result, data),
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn exact_plaintext_limit_fits_and_one_byte_more_is_rejected() {
    let mut crypto = UdpSessionCrypto::new(
        UdpSessionRole::Agent,
        SESSION_ID,
        MASTER_KEY,
        CLIENT_NONCE,
        SERVER_NONCE,
    )
    .unwrap();
    let datagrams = crypto
        .seal_message(0, &vec![0; UDP_MAX_MESSAGE_SIZE])
        .unwrap();
    assert!(datagrams.len() <= UDP_MAX_FRAGMENTS);
    assert!(
        datagrams
            .iter()
            .all(|packet| packet.len() <= UDP_MAX_DATAGRAM_SIZE)
    );
    assert_eq!(
        crypto.seal_message(1, &vec![0; UDP_MAX_MESSAGE_SIZE + 1]),
        Err(UdpTransportError::MessageTooLarge(UDP_MAX_MESSAGE_SIZE + 1))
    );
}

#[test]
fn single_fragment_reassembly_bypasses_full_fragment_buffers() {
    let start = Instant::now();
    let mut reassembler = FragmentReassembler::new(ReassemblyConfig {
        max_entries: 1,
        max_total_bytes: 1,
        timeout: Duration::from_secs(1),
    })
    .unwrap();

    assert!(
        reassembler
            .push(fragment(1, 0, 2, 2, b"a"), start)
            .unwrap()
            .is_none()
    );
    assert_eq!(reassembler.entry_count(), 1);
    assert_eq!(reassembler.buffered_bytes(), 1);

    assert_eq!(
        reassembler.push(fragment(2, 0, 1, 1, b"z"), start).unwrap(),
        Some(b"z".to_vec())
    );
    assert_eq!(reassembler.entry_count(), 1);
    assert_eq!(reassembler.buffered_bytes(), 1);
}

#[test]
fn new_fragmented_message_evicts_oldest_incomplete_message() {
    let start = Instant::now();
    let mut reassembler = FragmentReassembler::new(ReassemblyConfig {
        max_entries: 2,
        max_total_bytes: 100,
        timeout: Duration::from_secs(10),
    })
    .unwrap();

    reassembler.push(fragment(1, 0, 2, 2, b"a"), start).unwrap();
    reassembler
        .push(fragment(2, 0, 2, 2, b"b"), start + Duration::from_millis(1))
        .unwrap();
    reassembler
        .push(fragment(3, 0, 2, 2, b"c"), start + Duration::from_millis(2))
        .unwrap();

    assert_eq!(reassembler.entry_count(), 2);
    assert_eq!(reassembler.buffered_bytes(), 2);
    assert_eq!(
        reassembler
            .push(fragment(2, 1, 2, 2, b"d"), start + Duration::from_millis(3),)
            .unwrap(),
        Some(b"bd".to_vec())
    );
    assert_eq!(reassembler.entry_count(), 1);
    assert_eq!(reassembler.buffered_bytes(), 1);
}

#[test]
fn reassembly_byte_limit_evicts_only_as_many_other_messages_as_needed() {
    let start = Instant::now();
    let mut reassembler = FragmentReassembler::new(ReassemblyConfig {
        max_entries: 4,
        max_total_bytes: 5,
        timeout: Duration::from_secs(10),
    })
    .unwrap();

    reassembler
        .push(fragment(1, 0, 2, 4, b"aa"), start)
        .unwrap();
    reassembler
        .push(
            fragment(2, 0, 2, 4, b"bb"),
            start + Duration::from_millis(1),
        )
        .unwrap();
    reassembler
        .push(
            fragment(3, 0, 2, 4, b"ccc"),
            start + Duration::from_millis(2),
        )
        .unwrap();

    assert_eq!(reassembler.entry_count(), 2);
    assert_eq!(reassembler.buffered_bytes(), 5);
    assert_eq!(
        reassembler
            .push(fragment(3, 1, 2, 4, b"d"), start + Duration::from_millis(3),)
            .unwrap(),
        Some(b"cccd".to_vec())
    );
    assert_eq!(reassembler.entry_count(), 0);
    assert_eq!(reassembler.buffered_bytes(), 0);
}

#[test]
fn reassembly_rejects_a_current_message_that_cannot_fit_without_evicting_others() {
    let start = Instant::now();
    let mut reassembler = FragmentReassembler::new(ReassemblyConfig {
        max_entries: 2,
        max_total_bytes: 3,
        timeout: Duration::from_secs(10),
    })
    .unwrap();

    reassembler.push(fragment(1, 0, 2, 2, b"x"), start).unwrap();
    reassembler
        .push(
            fragment(2, 0, 2, 4, b"ab"),
            start + Duration::from_millis(1),
        )
        .unwrap();
    assert!(matches!(
        reassembler.push(
            fragment(2, 1, 2, 4, b"cd"),
            start + Duration::from_millis(2),
        ),
        Err(UdpTransportError::ReassemblyLimit(_))
    ));
    assert_eq!(reassembler.entry_count(), 2);
    assert_eq!(reassembler.buffered_bytes(), 3);
    assert_eq!(
        reassembler
            .push(fragment(1, 1, 2, 2, b"y"), start + Duration::from_millis(3),)
            .unwrap(),
        Some(b"xy".to_vec())
    );
}

#[test]
fn reassembly_enforces_fragment_and_timeout_limits() {
    let start = Instant::now();
    let mut reassembler = FragmentReassembler::new(ReassemblyConfig {
        max_entries: 1,
        max_total_bytes: 100,
        timeout: Duration::from_secs(1),
    })
    .unwrap();
    reassembler.push(fragment(1, 0, 2, 2, b"a"), start).unwrap();
    assert_eq!(
        reassembler.cleanup_expired(start + Duration::from_secs(1)),
        1
    );
    assert_eq!(reassembler.entry_count(), 0);
    assert_eq!(reassembler.buffered_bytes(), 0);

    let invalid_header = UdpPacketHeader::new(
        UdpPacketKind::Encrypted,
        SESSION_ID,
        0,
        0,
        0,
        (UDP_MAX_FRAGMENTS + 1) as u16,
        (UDP_MAX_FRAGMENTS + 1) as u32,
    );
    assert!(matches!(
        invalid_header.encode(),
        Err(UdpTransportError::TooManyFragments(_))
    ));
}

#[test]
fn all_session_message_variants_are_bitcode_serializable() {
    let messages = [
        UdpSessionMessage::Connect {
            flow_id: 1,
            address: Address::Ipv4 {
                addr: [127, 0, 0, 1],
                port: 53,
            },
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
            UdpSessionMessage::Connect { .. } => 0,
            UdpSessionMessage::ConnectResponse { .. } => 1,
            UdpSessionMessage::Data { .. } => 2,
            UdpSessionMessage::Close { .. } => 3,
            UdpSessionMessage::Ping { .. } => 4,
            UdpSessionMessage::Pong { .. } => 5,
        };
        assert_eq!(actual_index, expected_index);
    }
}
