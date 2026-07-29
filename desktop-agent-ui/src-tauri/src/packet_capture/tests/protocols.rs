use super::*;

#[test]
fn keeps_complete_payload_and_protocol_analysis() {
    let mut transport = vec![0u8; 20];
    transport[0..2].copy_from_slice(&50_000_u16.to_be_bytes());
    transport[2..4].copy_from_slice(&443_u16.to_be_bytes());
    transport[12] = 5 << 4;
    transport[13] = 0x18;
    transport.extend(0u8..80);

    let packet = build_packet(
        1,
        1_000,
        4,
        6,
        "10.0.0.2".to_string(),
        "1.1.1.1".to_string(),
        120,
        &transport,
    );

    assert_eq!(packet.payload_length, 80);
    assert_eq!(packet.payload_hex.split_whitespace().count(), 80);
    assert_eq!(packet.protocol_layers[0].name, "Frame");
    assert!(packet
        .protocol_layers
        .iter()
        .any(|layer| layer.name == "Transmission Control Protocol"));
}

#[test]
fn reassembles_segmented_tcp_application_protocol() {
    let first_payload = b"GET / HT";
    let second_payload = b"TP/1.1\r\nHost: example.com\r\n\r\n";
    let mut first_transport = vec![0u8; 20];
    first_transport[0..2].copy_from_slice(&50_000_u16.to_be_bytes());
    first_transport[2..4].copy_from_slice(&80_u16.to_be_bytes());
    first_transport[4..8].copy_from_slice(&1_000_u32.to_be_bytes());
    first_transport[12] = 5 << 4;
    first_transport[13] = 0x18;
    first_transport.extend_from_slice(first_payload);
    let mut second_transport = vec![0u8; 20];
    second_transport[0..2].copy_from_slice(&50_000_u16.to_be_bytes());
    second_transport[2..4].copy_from_slice(&80_u16.to_be_bytes());
    second_transport[4..8].copy_from_slice(&(1_000_u32 + first_payload.len() as u32).to_be_bytes());
    second_transport[12] = 5 << 4;
    second_transport[13] = 0x18;
    second_transport.extend_from_slice(second_payload);

    let mut packets = vec![
        build_packet(
            1,
            1_000,
            4,
            6,
            "10.0.0.2".to_string(),
            "1.1.1.1".to_string(),
            40 + first_payload.len(),
            &first_transport,
        ),
        build_packet(
            2,
            1_001,
            4,
            6,
            "10.0.0.2".to_string(),
            "1.1.1.1".to_string(),
            40 + second_payload.len(),
            &second_transport,
        ),
    ];

    analyze_reassembled_tcp_streams(&mut packets);

    assert!(packets[1]
        .protocol_layers
        .iter()
        .any(|layer| layer.name == "Reassembled TCP Stream"));
    assert!(packets[1].protocol_layers.iter().any(|layer| {
        layer.name == "Hypertext Transfer Protocol"
            && layer.summary.contains("reassembled from 2 segments")
    }));
    let http_layer = packets[1]
        .protocol_layers
        .iter()
        .find(|layer| layer.name == "Hypertext Transfer Protocol")
        .unwrap();
    assert!(http_layer
        .fields
        .iter()
        .any(|field| field.name == "Method" && field.value == "GET"));
    assert!(http_layer
        .fields
        .iter()
        .any(|field| field.name == "Header: Host" && field.value == "example.com"));
    assert_eq!(packets[1].sub_protocol.as_deref(), Some("HTTP"));
}

#[test]
fn decodes_dns_question_fields() {
    let mut dns = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    dns.extend_from_slice(b"\x07example\x03com\x00");
    dns.extend_from_slice(&1_u16.to_be_bytes());
    dns.extend_from_slice(&1_u16.to_be_bytes());

    let layer = analyze_application_protocol("UDP", Some(50_000), Some(53), &dns).unwrap();

    assert_eq!(layer.name, "Domain Name System");
    assert!(layer
        .fields
        .iter()
        .any(|field| field.name == "Query 1 name" && field.value == "example.com"));
    assert!(layer
        .fields
        .iter()
        .any(|field| field.name == "Query 1 type" && field.value == "1 (A)"));
}

#[test]
fn describes_encrypted_tls_application_payload() {
    let tls = [23, 3, 3, 0, 4, 1, 2, 3, 4];

    let layer = analyze_application_protocol("TCP", Some(50_000), Some(443), &tls).unwrap();

    assert_eq!(layer.name, "Transport Layer Security");
    assert!(layer.fields.iter().any(|field| {
        field.name == "Payload state" && field.value.contains("TLS session keys")
    }));
}

#[test]
fn identifies_http_connect_proxy_handshake() {
    let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";

    let layer = analyze_application_protocol("TCP", Some(51_000), Some(1080), request).unwrap();

    assert_eq!(layer.name, "Hypertext Transfer Protocol");
    assert_eq!(application_protocol_name(&layer), "HTTP");
    assert!(layer
        .fields
        .iter()
        .any(|field| field.name == "Method" && field.value == "CONNECT"));
}

#[test]
fn identifies_socks5_tcp_and_udp_messages() {
    let greeting = [5, 1, 0];
    let tcp_layer =
        analyze_application_protocol("TCP", Some(51_000), Some(1080), &greeting).unwrap();
    assert_eq!(tcp_layer.name, "SOCKS Version 5");
    assert_eq!(application_protocol_name(&tcp_layer), "SOCKS5");

    let udp_datagram = [0, 0, 0, 1, 203, 0, 113, 8, 0, 53, 1, 2, 3];
    let udp_layer =
        analyze_application_protocol("UDP", Some(51_001), Some(1081), &udp_datagram).unwrap();
    assert_eq!(udp_layer.name, "SOCKS Version 5 UDP Datagram");
    assert_eq!(application_protocol_name(&udp_layer), "SOCKS5");
    assert!(udp_layer
        .fields
        .iter()
        .any(|field| field.name == "Data length" && field.value == "3 bytes"));
}
