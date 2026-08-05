use proxy_entry::server::looks_like_yamux_header;

#[test]
fn recognizes_yamux_data_syn_header() {
    assert!(looks_like_yamux_header(&[0, 0, 0, 1]));
}

#[test]
fn recognizes_yamux_ping_header() {
    assert!(looks_like_yamux_header(&[0, 2, 0, 1]));
}

#[test]
fn rejects_direct_protocol_length_prefix() {
    assert!(!looks_like_yamux_header(&[0, 0, 1, 44]));
    assert!(!looks_like_yamux_header(&[0, 0, 4, 0]));
}

#[test]
fn rejects_invalid_yamux_flags() {
    assert!(!looks_like_yamux_header(&[0, 0, 0x10, 0]));
}
