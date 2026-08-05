use super::*;

#[test]
fn parses_http_connect_trace_and_socks5() {
    for request in [
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
        b"TRACE /debug HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
    ] {
        let layer = analyze_application("TCP", Some(50000), Some(18080), request).unwrap();
        assert_eq!(short_protocol(&layer.name), "HTTP");
        assert!(
            layer
                .fields
                .iter()
                .any(|field| field.name == "Header: Host" && field.value == "example.com")
        );
    }

    let layer = analyze_application("TCP", Some(50000), Some(18080), &[5, 1, 0]).unwrap();
    assert_eq!(short_protocol(&layer.name), "SOCKS5");
    assert!(layer.summary.contains("authentication method"));

    let binary_post =
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nX-Obs: \x80\r\nContent-Length: 1\r\n\r\n\xff";
    let layer = analyze_application("TCP", Some(50000), Some(18080), binary_post).unwrap();
    assert_eq!(short_protocol(&layer.name), "HTTP");
    assert!(
        layer
            .fields
            .iter()
            .any(|field| field.name == "Method" && field.value == "POST")
    );
}

#[test]
fn bounds_http_start_lines_and_header_values() {
    let mut request = b"GET /".to_vec();
    request.extend(std::iter::repeat_n(b'a', 64 * 1024));
    let layer = analyze_http(&request).expect("long request is still recognizable");
    assert!(layer.summary.chars().count() <= MAX_HTTP_START_LINE_BYTES + 1);
    let start_line = layer
        .fields
        .iter()
        .find(|field| field.name == "Start line")
        .expect("start line");
    assert!(start_line.value.chars().count() <= MAX_HTTP_START_LINE_BYTES + 1);

    let mut headers = b"GET / HTTP/1.1\r\nX-Long: ".to_vec();
    headers.extend(std::iter::repeat_n(b'b', 64 * 1024));
    headers.extend_from_slice(b"\r\n\r\n");
    let layer = analyze_http(&headers).expect("request with a long header");
    let value = layer
        .fields
        .iter()
        .find(|field| field.name == "Header: X-Long")
        .expect("bounded header value");
    assert!(value.value.chars().count() <= MAX_HTTP_HEADER_VALUE_BYTES + 1);
}

#[test]
fn tcp_reassembly_uses_syn_boundaries_and_tolerates_reordering_and_retransmission() {
    let client: SocketAddr = "127.0.0.1:51010".parse().unwrap();
    let server: SocketAddr = "127.0.0.1:18081".parse().unwrap();
    let first = b"GET / HTTP/1.1\r\n";
    let second = b"Host: example.com\r\n\r\n";
    let first_sequence = 10_001;
    let second_sequence = first_sequence + first.len() as u32;
    let first_end = second_sequence + second.len() as u32;
    let packets = [
        synthetic_tcp_packet_with_flags(client, server, 10_000, 0, TCP_FLAG_SYN, b"", 1),
        // Later bytes arrive before the beginning of the request.
        synthetic_tcp_packet(client, server, second_sequence, 0, second, 2),
        synthetic_tcp_packet(client, server, first_sequence, 0, first, 3),
        // A retransmission must remain in the same session.
        synthetic_tcp_packet(client, server, first_sequence, 0, first, 4),
        synthetic_tcp_packet_with_flags(client, server, first_end, 0, TCP_FLAG_FIN | 0x10, b"", 5),
        // A fresh SYN with a higher ISN is an unconditional boundary.
        synthetic_tcp_packet_with_flags(client, server, 90_000, 0, TCP_FLAG_SYN, b"", 6),
        synthetic_tcp_packet(client, server, 90_001, 0, b"POST /next HTTP/1.1\r\n\r\n", 7),
    ];
    let report = report_for_packets("tcp-session-boundaries", &packets, packets.len(), None);
    let reassembly_layers: Vec<_> = report
        .packets
        .iter()
        .flat_map(|packet| &packet.protocol_layers)
        .filter(|layer| layer.name == "Reassembled TCP Stream")
        .collect();
    assert_eq!(reassembly_layers.len(), 1);
    assert!(
        report
            .packets
            .iter()
            .flat_map(|packet| &packet.protocol_layers)
            .any(|layer| layer.name == "Hypertext Transfer Protocol"
                && layer.summary.contains("reassembled")
                && layer.summary.starts_with("GET "))
    );
    assert!(
        report.packets.iter().any(|packet| {
            packet.tcp_sequence == Some(90_001)
                && packet
                    .protocol_layers
                    .iter()
                    .all(|layer| layer.name != "Reassembled TCP Stream")
        }),
        "the post-SYN payload must not be joined to the prior connection"
    );
}

#[test]
fn closed_tuple_reuse_with_identical_syn_and_payload_starts_a_new_session() {
    let client: SocketAddr = "127.0.0.1:51018".parse().unwrap();
    let server: SocketAddr = "127.0.0.1:18089".parse().unwrap();
    let request = b"GET /same HTTP/1.1\r\n\r\n";
    let end = 4_001 + request.len() as u32;
    let packets = [
        synthetic_tcp_packet_with_flags(client, server, 4_000, 0, TCP_FLAG_SYN, b"", 1),
        synthetic_tcp_packet(client, server, 4_001, 0, request, 2),
        synthetic_tcp_packet_with_flags(client, server, end, 0, TCP_FLAG_FIN | 0x10, b"", 3),
        synthetic_tcp_packet_with_flags(client, server, 4_000, 0, TCP_FLAG_SYN, b"", 4),
        synthetic_tcp_packet(client, server, 4_001, 0, request, 5),
    ];

    let report = report_for_packets(
        "closed-identical-tuple-reuse",
        &packets,
        packets.len(),
        None,
    );
    assert_eq!(
        report
            .packets
            .iter()
            .flat_map(|packet| &packet.protocol_layers)
            .filter(|layer| layer.name == "Reassembled TCP Stream")
            .count(),
        0,
        "identical packets from separate closed connections must not be reassembled together"
    );
}

#[test]
fn syn_with_payload_and_fin_consume_tcp_sequence_space() {
    let client: SocketAddr = "127.0.0.1:51011".parse().unwrap();
    let server: SocketAddr = "127.0.0.1:18082".parse().unwrap();
    let packet = synthetic_tcp_packet_with_flags(
        client,
        server,
        4_000,
        0,
        TCP_FLAG_SYN | TCP_FLAG_FIN,
        b"abc",
        1,
    );
    let parsed = parse_ip_packet(1, 0, packet.len(), &packet).unwrap();
    assert_eq!(tcp_payload_sequence(&parsed), Some(4_001));
    assert_eq!(tcp_sequence_span(&parsed), 5);
}

#[test]
fn legacy_sequence_one_is_the_only_payload_fallback_boundary() {
    let client: SocketAddr = "127.0.0.1:51012".parse().unwrap();
    let server: SocketAddr = "127.0.0.1:18083".parse().unwrap();
    let http = b"GET / HTTP/1.1\r\n\r\n";
    let packets = [
        synthetic_tcp_packet(client, server, 1, 0, http, 1),
        // Lower/out-of-order data other than sequence 1 is not a reset.
        synthetic_tcp_packet(client, server, 8, 0, &http[7..], 2),
        // A different sequence-1 payload is the legacy synthetic reset.
        synthetic_tcp_packet(client, server, 1, 0, &[5, 1, 0], 3),
    ];
    let report = report_for_packets("legacy-sequence-one", &packets, packets.len(), None);
    assert!(
        report.packets[2]
            .protocol_layers
            .iter()
            .all(|layer| layer.name != "Reassembled TCP Stream")
    );
}

#[test]
fn legacy_identical_sequence_one_payload_resets_tracking_and_reassembly() {
    let client: SocketAddr = "127.0.0.1:51017".parse().unwrap();
    let proxy: SocketAddr = "127.0.0.1:18088".parse().unwrap();
    let greeting = [5, 1, 0];
    let request = [5, 1, 0, 1, 127, 0, 0, 1, 0, 80];
    let packets = [
        synthetic_tcp_packet(client, proxy, 1, 1, &greeting, 1),
        synthetic_tcp_packet(client, proxy, 4, 1, &request, 2),
        synthetic_tcp_packet(client, proxy, 1, 1, &greeting, 3),
        synthetic_tcp_packet(client, proxy, 4, 1, &request, 4),
    ];

    let parsed: Vec<_> = packets
        .iter()
        .enumerate()
        .map(|(index, packet)| {
            parse_ip_packet(index + 1, 0, packet.len(), packet).expect("synthetic TCP packet")
        })
        .collect();
    let key = flow_key(&parsed[0]);
    let mut tracker = ProxyFlowTracker::new(Some(proxy.port()));
    let sessions: Vec<_> = parsed
        .iter()
        .map(|packet| {
            tracker
                .observe(packet, &key)
                .expect("packet uses the proxy port")
                .session_id
        })
        .collect();
    assert_eq!(sessions[0], sessions[1]);
    assert_ne!(sessions[1], sessions[2]);
    assert_eq!(sessions[2], sessions[3]);

    let report = report_for_packets(
        "legacy-identical-sequence-one",
        &packets,
        packets.len(),
        Some(proxy.port()),
    );
    let reassembled_sessions = report
        .packets
        .iter()
        .flat_map(|packet| &packet.protocol_layers)
        .filter(|layer| layer.name == "Reassembled TCP Stream")
        .count();
    assert_eq!(reassembled_sessions, 2);
    assert!(
        report
            .packets
            .iter()
            .all(|packet| packet.proxy_protocol.as_deref() == Some("SOCKS5"))
    );
}

#[test]
fn packet_previews_and_reassembly_are_bounded_without_false_concatenation() {
    let client: SocketAddr = "127.0.0.1:51013".parse().unwrap();
    let server: SocketAddr = "127.0.0.1:18084".parse().unwrap();
    let large_payload = vec![b'x'; 48 * 1024];
    let next_payload = b"unrelated-tail";
    let packets = [
        synthetic_tcp_packet(client, server, 7_000, 0, &large_payload, 1),
        synthetic_tcp_packet(
            client,
            server,
            7_000 + large_payload.len() as u32,
            0,
            next_payload,
            2,
        ),
    ];
    let report = report_for_packets("bounded-payloads", &packets, packets.len(), None);
    let first = &report.packets[0];
    assert_eq!(first.payload_length, large_payload.len());
    assert_eq!(
        first.payload_preview_length,
        MAX_PACKET_PAYLOAD_PREVIEW_BYTES
    );
    assert!(first.payload_truncated);
    assert_eq!(first.payload_text.len(), MAX_PACKET_PAYLOAD_PREVIEW_BYTES);
    assert_eq!(
        first.payload_hex.len(),
        MAX_PACKET_PAYLOAD_PREVIEW_BYTES * 3 - 1
    );
    assert!(first.payload.is_empty());
    let reassembly = first
        .protocol_layers
        .iter()
        .find(|layer| layer.name == "Reassembled TCP Stream")
        .expect("truncated reassembly annotation");
    assert!(reassembly.summary.starts_with("Analyzed prefix"));
    assert!(
        reassembly
            .fields
            .iter()
            .any(|field| { field.name == "Reassembly truncated" && field.value == "true" })
    );
    assert!(
        report.packets[1]
            .protocol_layers
            .iter()
            .all(|layer| layer.name != "Reassembled TCP Stream"),
        "a segment after unavailable retained bytes must not be concatenated"
    );
}
