use super::*;

#[test]
fn parses_bidirectional_tcp_packets() {
    let upload = ipv4_tcp_packet([10, 0, 0, 2], [1, 1, 1, 1], 50_000, 443, 0x02);
    let download = ipv4_tcp_packet([1, 1, 1, 1], [10, 0, 0, 2], 443, 50_000, 0x12);
    let pcap = pcap_with_packets(&[upload, download]);
    let report = parse_pcap(&pcap, 100).unwrap();

    assert_eq!(report.total_packets, 2);
    assert_eq!(report.upload_packets, 1);
    assert_eq!(report.download_packets, 1);
    assert_eq!(report.packets[0].direction, "upload");
    assert_eq!(report.packets[1].direction, "download");
    assert_eq!(report.packets[0].protocol, "TCP");
}

#[test]
fn keeps_only_latest_packets_at_limit() {
    let packet = ipv4_tcp_packet([10, 0, 0, 2], [1, 1, 1, 1], 50_000, 443, 0x10);
    let pcap = pcap_with_packets(&[packet.clone(), packet.clone(), packet]);
    let report = parse_pcap(&pcap, 2).unwrap();

    assert_eq!(report.total_packets, 3);
    assert_eq!(report.returned_packets, 2);
    assert!(report.truncated);
    assert_eq!(report.packets[0].number, 2);
}

#[test]
fn keeps_proxy_protocol_on_later_tunnel_packets_after_handshake_is_truncated() {
    let http_handshake = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        51_000,
        10_080,
        1,
        b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
    );
    let socks_handshake = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        51_001,
        10_080,
        1,
        &[5, 1, 0],
    );
    let http_tunnel_data = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        51_000,
        10_080,
        41,
        &[1, 2, 3, 4],
    );
    let socks_tunnel_data = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        51_001,
        10_080,
        4,
        &[6, 7, 8, 9],
    );
    let pcap = pcap_with_packets(&[
        http_handshake,
        socks_handshake,
        http_tunnel_data,
        socks_tunnel_data,
    ]);

    let report = parse_pcap_for_proxy(&pcap, 2, 10_080).unwrap();

    assert_eq!(report.packets[0].number, 3);
    assert_eq!(report.packets[0].sub_protocol, None);
    assert_eq!(report.packets[0].proxy_protocol.as_deref(), Some("HTTP"));
    assert_eq!(report.packets[1].number, 4);
    assert_eq!(report.packets[1].sub_protocol, None);
    assert_eq!(report.packets[1].proxy_protocol.as_deref(), Some("SOCKS5"));
}

#[test]
fn keeps_reassembled_proxy_protocol_after_all_handshake_segments_are_truncated() {
    let first_payload = b"CONNEC";
    let first = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        51_002,
        10_080,
        1,
        first_payload,
    );
    let second_payload = b"T example.com:443 HTTP/1.1\r\n\r\n";
    let second = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        51_002,
        10_080,
        1 + first_payload.len() as u32,
        second_payload,
    );
    let tunnel_data = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        51_002,
        10_080,
        1 + first_payload.len() as u32 + second_payload.len() as u32,
        &[1, 2, 3, 4],
    );
    let pcap = pcap_with_packets(&[first, second, tunnel_data]);

    let report = parse_pcap_for_proxy(&pcap, 1, 10_080).unwrap();

    assert_eq!(report.packets[0].number, 3);
    assert_eq!(report.packets[0].sub_protocol, None);
    assert_eq!(report.packets[0].proxy_protocol.as_deref(), Some("HTTP"));
}

#[test]
fn proxy_protocol_does_not_label_unrelated_http_or_socks_like_tcp() {
    let ordinary_http = ipv4_tcp_payload_packet(
        [10, 0, 0, 2],
        [203, 0, 113, 8],
        52_000,
        80,
        1,
        b"GET / HTTP/1.1\r\n\r\n",
    );
    let socks_like_payload =
        ipv4_tcp_payload_packet([10, 0, 0, 2], [203, 0, 113, 9], 52_001, 443, 1, &[5, 1, 0]);
    let pcap = pcap_with_packets(&[ordinary_http, socks_like_payload]);

    let report = parse_pcap_for_proxy(&pcap, 10, 10_080).unwrap();

    assert_eq!(report.packets[0].sub_protocol.as_deref(), Some("HTTP"));
    assert_eq!(report.packets[0].proxy_protocol, None);
    assert_eq!(report.packets[1].sub_protocol, None);
    assert_eq!(report.packets[1].proxy_protocol, None);
}

#[test]
fn proxy_protocol_resets_when_a_tcp_tuple_is_reused() {
    let http_request = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
    let http_handshake = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_000,
        10_080,
        1,
        http_request,
    );
    let http_data = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_000,
        10_080,
        1 + http_request.len() as u32,
        &[1, 2, 3],
    );
    let socks_handshake = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_000,
        10_080,
        1,
        &[5, 1, 0],
    );
    let socks_data = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_000,
        10_080,
        4,
        &[6, 7, 8],
    );
    let pcap = pcap_with_packets(&[http_handshake, http_data, socks_handshake, socks_data]);

    let report = parse_pcap_for_proxy(&pcap, 10, 10_080).unwrap();

    assert_eq!(report.packets[0].proxy_protocol.as_deref(), Some("HTTP"));
    assert_eq!(report.packets[1].proxy_protocol.as_deref(), Some("HTTP"));
    assert_eq!(report.packets[2].proxy_protocol.as_deref(), Some("SOCKS5"));
    assert_eq!(report.packets[3].proxy_protocol.as_deref(), Some("SOCKS5"));
}

#[test]
fn reused_tcp_tuple_does_not_inherit_an_old_proxy_protocol() {
    let first_payload = b"CONNEC";
    let second_payload = b"T example.com:443 HTTP/1.1\r\n\r\n";
    let old_http_first = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_001,
        10_080,
        1,
        first_payload,
    );
    let old_http_second = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_001,
        10_080,
        1 + first_payload.len() as u32,
        second_payload,
    );
    let new_unknown = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_001,
        10_080,
        1,
        &[1, 2, 3, 4],
    );
    let new_response = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        10_080,
        53_001,
        1,
        &[6, 7, 8, 9],
    );
    let pcap = pcap_with_packets(&[old_http_first, old_http_second, new_unknown, new_response]);

    let report = parse_pcap_for_proxy(&pcap, 10, 10_080).unwrap();

    assert_eq!(report.packets[1].proxy_protocol.as_deref(), Some("HTTP"));
    assert_eq!(report.packets[2].proxy_protocol, None);
    assert_eq!(report.packets[2].sub_protocol, None);
    assert_eq!(report.packets[3].proxy_protocol, None);
    assert_eq!(report.packets[3].sub_protocol, None);
}

#[test]
fn known_http_tunnel_does_not_show_a_spurious_socks5_inner_protocol() {
    let http_request = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
    let http_handshake = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_002,
        10_080,
        1,
        http_request,
    );
    let socks_like_tunnel_data = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_002,
        10_080,
        1 + http_request.len() as u32,
        &[5, 1, 0],
    );
    let pcap = pcap_with_packets(&[http_handshake, socks_like_tunnel_data]);

    let report = parse_pcap_for_proxy(&pcap, 10, 10_080).unwrap();

    assert_eq!(report.packets[1].proxy_protocol.as_deref(), Some("HTTP"));
    assert_ne!(report.packets[1].sub_protocol.as_deref(), Some("SOCKS5"));
    assert!(report.packets[1]
        .protocol_layers
        .iter()
        .all(|layer| layer.name != "SOCKS Version 5"));
}

#[test]
fn reassembled_http_tunnel_data_does_not_restore_a_spurious_socks5_protocol() {
    let http_request = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
    let http_handshake = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_004,
        10_080,
        1,
        http_request,
    );
    let tunnel_first = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_004,
        10_080,
        1 + http_request.len() as u32,
        &[5],
    );
    let tunnel_second = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_004,
        10_080,
        2 + http_request.len() as u32,
        &[1, 0],
    );
    let pcap = pcap_with_packets(&[http_handshake, tunnel_first, tunnel_second]);

    let report = parse_pcap_for_proxy(&pcap, 2, 10_080).unwrap();

    assert_eq!(report.packets[1].proxy_protocol.as_deref(), Some("HTTP"));
    assert_ne!(report.packets[1].sub_protocol.as_deref(), Some("SOCKS5"));
    assert!(report.packets[1]
        .protocol_layers
        .iter()
        .all(|layer| layer.name != "SOCKS Version 5"));
}

#[test]
fn reassembled_socks_like_bytes_off_the_proxy_port_are_not_labeled_socks5() {
    let first = ipv4_tcp_payload_packet([10, 0, 0, 2], [203, 0, 113, 9], 53_005, 443, 1, &[5]);
    let second = ipv4_tcp_payload_packet([10, 0, 0, 2], [203, 0, 113, 9], 53_005, 443, 2, &[1, 0]);
    let pcap = pcap_with_packets(&[first, second]);

    let report = parse_pcap_for_proxy(&pcap, 10, 10_080).unwrap();

    assert!(report
        .packets
        .iter()
        .all(|packet| packet.sub_protocol.as_deref() != Some("SOCKS5")));
    assert!(report.packets.iter().all(|packet| {
        packet
            .protocol_layers
            .iter()
            .all(|layer| layer.name != "SOCKS Version 5")
    }));
}

#[test]
fn explicit_proxy_direction_uses_the_listen_port_even_when_response_is_first() {
    let response = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        10_080,
        53_003,
        1,
        b"HTTP/1.1 200 Connection established\r\n\r\n",
    );
    let request = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        53_003,
        10_080,
        1,
        b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
    );
    let pcap = pcap_with_packets(&[response, request]);

    let report = parse_pcap_for_proxy(&pcap, 10, 10_080).unwrap();

    assert_eq!(report.packets[0].direction, "download");
    assert_eq!(report.packets[1].direction, "upload");
    assert_eq!(report.download_packets, 1);
    assert_eq!(report.upload_packets, 1);
}

#[test]
fn reassembled_connect_marks_the_following_proxy_response() {
    let first_payload = b"CONNEC";
    let second_payload = b"T example.com:443 HTTP/1.1\r\n\r\n";
    let first = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        54_000,
        10_080,
        1,
        first_payload,
    );
    let second = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        54_000,
        10_080,
        1 + first_payload.len() as u32,
        second_payload,
    );
    let response = ipv4_tcp_payload_packet(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        10_080,
        54_000,
        1,
        &[1, 2, 3],
    );
    let pcap = pcap_with_packets(&[first, second, response]);

    let report = parse_pcap_for_proxy(&pcap, 10, 10_080).unwrap();

    assert_eq!(report.packets[1].sub_protocol.as_deref(), Some("HTTP"));
    assert_eq!(report.packets[1].proxy_protocol.as_deref(), Some("HTTP"));
    assert_eq!(report.packets[2].proxy_protocol.as_deref(), Some("HTTP"));
}
