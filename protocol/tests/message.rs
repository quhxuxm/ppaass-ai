use bytes::BytesMut;
use protocol::message::PROTOCOL_VERSION;
use protocol::tcp_transport::{AuthFailureCode, TCP_HANDSHAKE_VERSION};
use protocol::{Address, AuthResponse, CipherState, MessageCodec, MessageType};
use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::codec::Decoder;

#[test]
fn equal_addresses_can_be_used_as_hash_map_keys() {
    let address = Address::Domain {
        host: "www.youtube.com".to_string(),
        port: 443,
    };
    let mut addresses = HashMap::new();
    addresses.insert(address.clone(), 7_u64);

    assert_eq!(addresses.get(&address), Some(&7));
    assert_eq!(addresses.len(), 1);
}

#[test]
fn address_port_is_part_of_equality_and_hashing() {
    let https = Address::Ipv4 {
        addr: [142, 250, 72, 206],
        port: 443,
    };
    let dns = Address::Ipv4 {
        addr: [142, 250, 72, 206],
        port: 53,
    };
    let mut addresses = HashMap::new();
    addresses.insert(https, "https");
    addresses.insert(dns, "dns");

    assert_eq!(addresses.len(), 2);
}

#[test]
fn structured_and_generic_failures_have_safe_shapes() {
    let structured = AuthResponse::terminal_failure(AuthFailureCode::UserExpired, "User expired");
    structured.validate_shape().unwrap();

    let generic = AuthResponse::failure("Authentication failed");
    generic.validate_shape().unwrap();
    assert_eq!(generic.failure_code, None);
}

#[test]
fn successful_response_cannot_carry_a_failure_code() {
    let mut response = AuthResponse::success(vec![1_u8; 256]);
    response.failure_code = Some(AuthFailureCode::UserExpired);
    assert!(response.validate_shape().is_err());
}

#[test]
fn serde_default_keeps_code_less_failures_generic() {
    let response: AuthResponse = serde_json::from_value(serde_json::json!({
        "version": TCP_HANDSHAKE_VERSION,
        "success": false,
        "message": "legacy failure",
        "encrypted_session": []
    }))
    .unwrap();
    assert_eq!(response.failure_code, None);
    response.validate_shape().unwrap();
}

#[test]
fn oversized_preauth_length_prefix_is_rejected_immediately() {
    let mut codec = MessageCodec::new(Arc::new(CipherState::new()));
    let mut input = BytesMut::from(&u32::MAX.to_be_bytes()[..]);

    assert!(codec.decode(&mut input).is_err());
    assert_eq!(input.len(), 4);
}

#[test]
fn previous_tcp_protocol_envelope_has_no_fallback() {
    let mut encoded = vec![PROTOCOL_VERSION - 1, MessageType::AuthRequest as u8, 0];
    encoded.extend_from_slice(&0_u64.to_be_bytes());
    let mut input = BytesMut::new();
    input.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    input.extend_from_slice(&encoded);
    let mut codec = MessageCodec::new(Arc::new(CipherState::new()));

    assert!(codec.decode(&mut input).is_err());
}
