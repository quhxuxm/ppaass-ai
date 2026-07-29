use super::*;

#[test]
fn retained_window_direction_state_is_bounded_and_stable() {
    let client: SocketAddr = "127.0.0.1:51014".parse().unwrap();
    let server: SocketAddr = "127.0.0.1:18085".parse().unwrap();
    let upload_bytes = synthetic_tcp_packet(client, server, 1, 0, b"a", 1);
    let download_bytes = synthetic_tcp_packet(server, client, 1, 0, b"b", 2);
    let mut upload =
        parse_ip_packet(1, 0, upload_bytes.len(), &upload_bytes).expect("upload packet");
    let mut download =
        parse_ip_packet(2, 0, download_bytes.len(), &download_bytes).expect("download packet");
    upload.direction_tracked = true;
    download.direction_tracked = true;
    let key = flow_key(&upload);
    let mut tracker = WindowDirectionTracker::default();
    assert_eq!(tracker.observe(&upload, &key), "upload");
    assert_eq!(tracker.observe(&download, &key), "download");
    tracker.release(&upload, &key);
    assert_eq!(tracker.observe(&upload, &key), "upload");
    tracker.release(&download, &key);
    tracker.release(&upload, &key);
    assert!(tracker.flows.is_empty());
}

#[test]
fn report_ignores_a_record_crossing_its_file_snapshot() {
    let path = temporary_capture_path("partial-report-record");
    let client: SocketAddr = "127.0.0.1:51015".parse().unwrap();
    let server: SocketAddr = "127.0.0.1:18086".parse().unwrap();
    let packet = synthetic_tcp_packet(client, server, 1, 0, b"complete", 1);
    let mut bytes = pcap_bytes(&[packet]);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&100u32.to_le_bytes());
    bytes.extend_from_slice(&100u32.to_le_bytes());
    bytes.extend_from_slice(b"partial");
    fs::write(&path, bytes).unwrap();

    let report = read_report(&path, 10, None).unwrap();
    assert_eq!(report.total_packets, 1);
    assert_eq!(report.packets.len(), 1);
    fs::remove_file(path).unwrap();
}

#[test]
fn report_returns_while_the_capture_is_continuously_appended() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc as std_mpsc;

    let path = temporary_capture_path("live-report-snapshot");
    let client: SocketAddr = "127.0.0.1:51016".parse().unwrap();
    let server: SocketAddr = "127.0.0.1:18087".parse().unwrap();
    let packet = synthetic_tcp_packet(client, server, 1, 0, b"x", 1);
    let initial_packets = vec![packet.clone(); 20_000];
    fs::write(&path, pcap_bytes(&initial_packets)).unwrap();

    let keep_writing = Arc::new(AtomicBool::new(true));
    let writer_flag = keep_writing.clone();
    let writer_path = path.clone();
    let mut record = Vec::with_capacity(16 + packet.len());
    record.extend_from_slice(&1u32.to_le_bytes());
    record.extend_from_slice(&0u32.to_le_bytes());
    record.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    record.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    record.extend_from_slice(&packet);
    let batch = record.repeat(128);
    let writer = thread::spawn(move || {
        let mut file = OpenOptions::new().append(true).open(writer_path).unwrap();
        while writer_flag.load(Ordering::Relaxed) {
            file.write_all(&batch).unwrap();
            file.flush().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
    });

    let (result_sender, result_receiver) = std_mpsc::channel();
    let reader_path = path.clone();
    let reader = thread::spawn(move || {
        let _ = result_sender.send(read_report(&reader_path, 10, None));
    });
    let result = result_receiver.recv_timeout(Duration::from_secs(5));
    keep_writing.store(false, Ordering::Relaxed);
    writer.join().unwrap();
    reader.join().unwrap();
    let report = result
        .expect("snapshot-bounded report must return while writes continue")
        .unwrap();
    assert!(fs::metadata(&path).unwrap().len() > report.file_size);
    fs::remove_file(path).unwrap();
}

#[test]
fn proxy_protocol_survives_retention_and_segmented_handshakes() {
    let client: SocketAddr = "127.0.0.1:51000".parse().unwrap();
    let proxy: SocketAddr = "127.0.0.1:18080".parse().unwrap();
    let prefix = b"CONNE";
    let suffix = b"CT example.com:443 HTTP/1.1\r\n\r\n";
    let http = report_for_packets(
        "http-flow-label",
        &[
            synthetic_tcp_packet(client, proxy, 1, 1, prefix, 1),
            synthetic_tcp_packet(client, proxy, 1 + prefix.len() as u32, 1, suffix, 2),
            synthetic_tcp_packet(
                proxy,
                client,
                1,
                1 + (prefix.len() + suffix.len()) as u32,
                &[22, 3, 3, 0, 1, 0],
                3,
            ),
        ],
        3,
        Some(proxy.port()),
    );
    assert_eq!(http.packets.len(), 3);
    assert!(
        http.packets
            .iter()
            .all(|packet| packet.proxy_protocol.as_deref() == Some("HTTP"))
    );
    assert_eq!(http.packets[0].direction, "upload");
    assert_eq!(http.packets[2].direction, "download");

    let socks = report_for_packets(
        "socks-flow-label",
        &[
            synthetic_tcp_packet(client, proxy, 1, 1, &[5, 1, 0], 1),
            synthetic_tcp_packet(proxy, client, 1, 4, &[22, 3, 3, 0, 1, 0], 2),
        ],
        1,
        Some(proxy.port()),
    );
    assert_eq!(socks.packets.len(), 1);
    assert_eq!(socks.packets[0].proxy_protocol.as_deref(), Some("SOCKS5"));
    assert_eq!(socks.packets[0].direction, "download");
}

#[test]
fn legacy_proxy_tracking_handles_out_of_order_handshakes_and_sequence_wrap() {
    let client: SocketAddr = "127.0.0.1:51001".parse().unwrap();
    let proxy: SocketAddr = "127.0.0.1:18080".parse().unwrap();
    let out_of_order = report_for_packets(
        "legacy-out-of-order-handshake",
        &[
            synthetic_tcp_packet_with_flags(client, proxy, 1_000, 0, TCP_FLAG_SYN, b"", 1),
            synthetic_tcp_packet(client, proxy, 1_006, 0, b"CT / HTTP/1.1\r\n\r\n", 2),
            synthetic_tcp_packet(client, proxy, 1_001, 0, b"CONNE", 3),
        ],
        3,
        Some(proxy.port()),
    );
    assert!(
        out_of_order
            .packets
            .iter()
            .all(|packet| packet.proxy_protocol.as_deref() == Some("HTTP"))
    );

    let wrapped = report_for_packets(
        "legacy-sequence-wrap",
        &[
            synthetic_tcp_packet(client, proxy, u32::MAX - 2, 0, b"CONN", 1),
            synthetic_tcp_packet(client, proxy, 1, 0, b"ECT / HTTP/1.1\r\n\r\n", 2),
        ],
        2,
        Some(proxy.port()),
    );
    assert!(
        wrapped
            .packets
            .iter()
            .all(|packet| packet.proxy_protocol.as_deref() == Some("HTTP"))
    );
}

#[test]
fn legacy_sequence_wrap_is_only_a_boundary_while_one_is_expected() {
    let client: SocketAddr = "127.0.0.1:51019".parse().unwrap();
    let proxy: SocketAddr = "127.0.0.1:18091".parse().unwrap();
    let suffix = b"ECT / HTTP/1.1\r\n\r\n";
    let packets = [
        synthetic_tcp_packet(client, proxy, u32::MAX - 2, 0, b"CONN", 1),
        synthetic_tcp_packet(client, proxy, 1, 0, suffix, 2),
        synthetic_tcp_packet(client, proxy, 1, 0, suffix, 3),
    ];
    let report = report_for_packets(
        "legacy-current-sequence-wrap",
        &packets,
        packets.len(),
        Some(proxy.port()),
    );

    assert_eq!(report.packets[0].proxy_protocol.as_deref(), Some("HTTP"));
    assert_eq!(report.packets[1].proxy_protocol.as_deref(), Some("HTTP"));
    assert_eq!(report.packets[2].proxy_protocol, None);
    assert!(
        report.packets[1]
            .protocol_layers
            .iter()
            .any(|layer| layer.name == "Reassembled TCP Stream")
    );
    assert!(
        report.packets[1]
            .protocol_layers
            .iter()
            .any(|layer| layer.name == "Hypertext Transfer Protocol"
                && layer.summary.contains("reassembled"))
    );
    assert!(
        report.packets[2]
            .protocol_layers
            .iter()
            .all(|layer| layer.name != "Reassembled TCP Stream")
    );
}

#[test]
fn embedded_proxy_markers_survive_port_changes_and_mid_tunnel_payloads() {
    let client: SocketAddr = "127.0.0.1:51000".parse().unwrap();
    let proxy: SocketAddr = "127.0.0.1:18080".parse().unwrap();
    let packets = [
        synthetic_proxy_tcp_packet(
            client,
            proxy,
            9_000,
            7_000,
            &[22, 3, 3, 0, 1, 0],
            1,
            ProxyPacketMarker {
                protocol: ProxyIngressProtocol::Http,
                direction: ProxyPacketDirection::Upload,
            },
        ),
        synthetic_proxy_tcp_packet(
            proxy,
            client,
            7_000,
            9_006,
            b"GET /inside-socks HTTP/1.1\r\n\r\n",
            2,
            ProxyPacketMarker {
                protocol: ProxyIngressProtocol::Socks5,
                direction: ProxyPacketDirection::Download,
            },
        ),
    ];

    let report = report_for_packets("marked-proxy", &packets, 2, Some(19090));

    assert_eq!(report.packets[0].proxy_protocol.as_deref(), Some("HTTP"));
    assert_eq!(report.packets[0].direction, "upload");
    assert_eq!(report.packets[1].proxy_protocol.as_deref(), Some("SOCKS5"));
    assert_eq!(report.packets[1].direction, "download");
    assert_eq!(report.packets[1].sub_protocol.as_deref(), Some("HTTP"));
}

#[test]
fn proxy_protocol_is_port_scoped_and_resets_on_tuple_reuse() {
    let client: SocketAddr = "127.0.0.1:51000".parse().unwrap();
    let proxy: SocketAddr = "127.0.0.1:18080".parse().unwrap();
    let unrelated_http: SocketAddr = "203.0.113.10:80".parse().unwrap();
    let unrelated_tls: SocketAddr = "203.0.113.20:443".parse().unwrap();
    let unrelated = report_for_packets(
        "unrelated-protocols",
        &[
            synthetic_tcp_packet(client, unrelated_http, 1, 1, b"GET / HTTP/1.1\r\n\r\n", 1),
            synthetic_tcp_packet(client, unrelated_tls, 1, 1, &[5, 1, 0], 2),
        ],
        2,
        Some(proxy.port()),
    );
    assert!(
        unrelated
            .packets
            .iter()
            .all(|packet| packet.proxy_protocol.is_none())
    );
    assert_ne!(unrelated.packets[1].sub_protocol.as_deref(), Some("SOCKS5"));

    let http_request = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
    let reused = report_for_packets(
        "tuple-reuse",
        &[
            synthetic_tcp_packet(client, proxy, 1, 1, http_request, 1),
            synthetic_tcp_packet(
                client,
                proxy,
                1 + http_request.len() as u32,
                1,
                &[22, 3, 3, 0, 1, 0],
                2,
            ),
            synthetic_tcp_packet(client, proxy, 1, 1, &[5, 1, 0], 3),
            synthetic_tcp_packet(proxy, client, 1, 4, &[5, 0], 4),
        ],
        4,
        Some(proxy.port()),
    );
    assert_eq!(reused.packets[1].proxy_protocol.as_deref(), Some("HTTP"));
    assert_eq!(reused.packets[2].proxy_protocol.as_deref(), Some("SOCKS5"));
    assert_eq!(reused.packets[3].proxy_protocol.as_deref(), Some("SOCKS5"));
}
