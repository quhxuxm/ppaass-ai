use desktop_agent_ui::network::{
    is_quic_version_negotiation_response, quic_version_negotiation_probe,
};

#[test]
fn quic_probe_uses_reserved_version_and_minimum_size() {
    let packet = quic_version_negotiation_probe();

    assert_eq!(packet.len(), 1200);
    assert_eq!(packet[0], 0xc0);
    assert_eq!(
        u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]),
        0x0a0a0a0a
    );
    assert_eq!(packet[5], 8);
    assert_eq!(packet[14], 8);
}

#[test]
fn recognizes_quic_version_negotiation_response() {
    assert!(is_quic_version_negotiation_response(&[
        0xc0, 0, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8
    ]));
    assert!(!is_quic_version_negotiation_response(&[
        0xc0, 0, 0, 0, 1, 8, 1, 2
    ]));
    assert!(!is_quic_version_negotiation_response(&[
        0x40, 0, 0, 0, 0, 8, 1
    ]));
}
