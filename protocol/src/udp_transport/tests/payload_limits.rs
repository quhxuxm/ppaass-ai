use super::*;

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
            .encode_message(&UdpSessionMessage::OpenData {
                flow_id: u64::MAX,
                address: Address::UdpRelay,
                data: relay_packet,
            })
            .unwrap();

        assert_eq!(
            datagrams.len(),
            1,
            "OpenData lengths: {:?}",
            datagrams.iter().map(Vec::len).collect::<Vec<_>>()
        );
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
