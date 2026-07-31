use super::*;

#[test]
fn defaults_bound_each_session_without_reducing_message_limit() {
    let config = ReassemblyConfig::default();

    assert_eq!(config.max_entries, 64);
    assert_eq!(config.max_total_bytes, 1024 * 1024);
    assert_eq!(config.timeout, Duration::from_secs(1));
    assert!(config.max_total_bytes >= UDP_MAX_MESSAGE_SIZE);
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
            .push(fragment(2, 1, 2, 2, b"d"), start + Duration::from_millis(3))
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
            .push(fragment(3, 1, 2, 4, b"d"), start + Duration::from_millis(3))
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
            .push(fragment(1, 1, 2, 2, b"y"), start + Duration::from_millis(3))
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
