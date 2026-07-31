use super::*;

#[test]
fn reopening_capture_appends_repairs_tail_and_preserves_incompatible_files() {
    let path = temporary_capture_path("append");
    let first = PacketWriter::open_or_append(&path).unwrap();
    first.record(&[0x45, 0, 0, 20]).unwrap();
    drop(first);
    let first_len = fs::metadata(&path).unwrap().len();

    let mut partial_record = [0u8; 19];
    partial_record[8..12].copy_from_slice(&10u32.to_le_bytes());
    partial_record[12..16].copy_from_slice(&10u32.to_le_bytes());
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&partial_record)
        .unwrap();

    let second = PacketWriter::open_or_append(&path).unwrap();
    second.record(&[0x45, 0, 0, 21]).unwrap();
    drop(second);
    let bytes = fs::read(&path).unwrap();
    assert!(bytes.len() as u64 > first_len);
    let packets = read_pcap_packets(&bytes);
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0], [0x45, 0, 0, 20]);
    assert_eq!(packets[1], [0x45, 0, 0, 21]);
    fs::remove_file(path).unwrap();

    let incompatible_path = temporary_capture_path("incompatible");
    let incompatible = b"not a compatible pcap";
    fs::write(&incompatible_path, incompatible).unwrap();
    let error = match PacketWriter::open_or_append(&incompatible_path) {
        Ok(_) => panic!("incompatible PCAP must not be overwritten"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert_eq!(fs::read(&incompatible_path).unwrap(), incompatible);
    fs::remove_file(incompatible_path).unwrap();
}

#[test]
fn append_validation_scans_many_records_through_a_bounded_number_of_reads() {
    struct CountingReader {
        inner: Cursor<Vec<u8>>,
        reads: Rc<Cell<usize>>,
    }

    impl Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            Read::read(&mut self.inner, buffer)
        }
    }

    let packet = [0x45u8; 32];
    let record_count = 20_000u32;
    let mut bytes = global_header().to_vec();
    for index in 0..record_count {
        bytes.extend_from_slice(&index.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&packet);
    }
    let expected_len = bytes.len() as u64;
    let reads = Rc::new(Cell::new(0));
    let counting = CountingReader {
        inner: Cursor::new(bytes),
        reads: reads.clone(),
    };
    let mut reader = BufReader::with_capacity(64 * 1024, counting);

    assert_eq!(
        scan_compatible_capture(&mut reader, expected_len).unwrap(),
        expected_len
    );
    assert!(
        reads.get() < 64,
        "buffered scan used {} reads for {record_count} records",
        reads.get()
    );
}

#[test]
fn disabled_capture_bytes_advance_synthetic_tcp_sequence() {
    let _guard = capture_runtime_test_lock().blocking_lock();
    let path = temporary_capture_path("capture-toggle-gap");
    set_enabled(path.clone(), false).unwrap();
    set_enabled(path.clone(), true).unwrap();
    let mut flow = TcpCaptureFlow::new(
        "127.0.0.1:51000".parse().unwrap(),
        "127.0.0.1:18080".parse().unwrap(),
        ProxyIngressProtocol::Http,
    );

    flow.record_client_to_server(b"before");
    set_enabled(path.clone(), false).unwrap();
    flow.record_client_to_server(b"not-captured");
    set_enabled(path.clone(), true).unwrap();
    flow.record_client_to_server(b"after");
    set_enabled(path.clone(), false).unwrap();

    let bytes = fs::read(&path).unwrap();
    let packets = read_pcap_packets(&bytes);
    let before = packets
        .iter()
        .copied()
        .find(|packet| tcp_payload(packet) == b"before")
        .unwrap();
    let after = packets
        .iter()
        .copied()
        .find(|packet| tcp_payload(packet) == b"after")
        .unwrap();
    assert_eq!(tcp_sequence(before), 1);
    assert_eq!(
        tcp_sequence(after),
        1 + b"before".len() as u32 + b"not-captured".len() as u32
    );
    fs::remove_file(path).unwrap();
}

#[test]
fn synthetic_proxy_payloads_are_split_into_bounded_marked_packets() {
    let _guard = capture_runtime_test_lock().blocking_lock();
    let path = temporary_capture_path("bounded-synthetic-packets");
    set_enabled(path.clone(), false).unwrap();
    set_enabled(path.clone(), true).unwrap();
    let mut flow = TcpCaptureFlow::new(
        "127.0.0.1:51020".parse().unwrap(),
        "127.0.0.1:18090".parse().unwrap(),
        ProxyIngressProtocol::Socks5,
    );
    let payload = vec![b'z'; MAX_SYNTHETIC_TCP_PAYLOAD + 17];
    flow.record_client_to_server(&payload);
    set_enabled(path.clone(), false).unwrap();

    let bytes = fs::read(&path).unwrap();
    let packets = read_pcap_packets(&bytes);
    assert_eq!(CAPTURE_QUEUE_PACKETS, 1_024);
    assert_eq!(packets.len(), 2);
    assert_eq!(tcp_payload(packets[0]).len(), MAX_SYNTHETIC_TCP_PAYLOAD);
    assert_eq!(tcp_payload(packets[1]).len(), 17);
    assert_eq!(tcp_sequence(packets[0]), 1);
    assert_eq!(
        tcp_sequence(packets[1]),
        1 + MAX_SYNTHETIC_TCP_PAYLOAD as u32
    );
    for packet in packets {
        let parsed = parse_ip_packet(1, 0, packet.len(), packet).unwrap();
        assert_eq!(
            parsed.proxy_marker,
            Some(ProxyPacketMarker {
                protocol: ProxyIngressProtocol::Socks5,
                direction: ProxyPacketDirection::Upload,
            })
        );
        assert!(!tcp_has_flag(&parsed, TCP_FLAG_SYN));
        assert!(!tcp_has_flag(&parsed, TCP_FLAG_FIN));
    }
    fs::remove_file(path).unwrap();
}

#[test]
fn failed_writer_is_not_enabled_and_can_be_replaced() {
    let _guard = capture_runtime_test_lock().blocking_lock();
    let path = temporary_capture_path("failed-writer-replacement");
    set_enabled(path.clone(), false).unwrap();
    set_enabled(path.clone(), true).unwrap();
    let failed_health = active_writer_health().expect("active writer");
    failed_health.mark_failed("injected test failure");
    assert!(!is_enabled());

    set_enabled(path.clone(), true).unwrap();
    let replacement_health = active_writer_health().expect("replacement writer");
    assert!(replacement_health.is_healthy());
    assert!(!Arc::ptr_eq(&failed_health, &replacement_health));

    record(&[0x45, 0, 0, 20]);
    set_enabled(path.clone(), false).unwrap();
    assert_eq!(read_pcap_packets(&fs::read(&path).unwrap()).len(), 1);
    fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn captured_tcp_stream_records_both_directions_without_changing_io() {
    let _guard = capture_runtime_test_lock().lock().await;
    let path = temporary_capture_path("proxy-stream");
    set_enabled(path.clone(), false).unwrap();
    set_enabled(path.clone(), true).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let mut captured = capture_tcp_stream(server, ProxyIngressProtocol::Http);

    client.write_all(b"proxy request").await.unwrap();
    let mut request = [0u8; 13];
    captured.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"proxy request");

    captured.write_all(b"proxy response").await.unwrap();
    let mut response = [0u8; 14];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"proxy response");

    drop(captured);
    drop(client);
    set_enabled(path.clone(), false).unwrap();

    let bytes = fs::read(&path).unwrap();
    let packets = read_pcap_packets(&bytes);
    let request_packet = packets
        .iter()
        .copied()
        .find(|packet| tcp_payload(packet) == b"proxy request")
        .expect("captured request");
    let response_packet = packets
        .iter()
        .copied()
        .find(|packet| tcp_payload(packet) == b"proxy response")
        .expect("captured response");
    let first_tcp = &request_packet[IPV4_HEADER_LEN..];
    let second_tcp = &response_packet[IPV4_HEADER_LEN..];
    assert_eq!(
        u16::from_be_bytes(first_tcp[..2].try_into().unwrap()),
        client_addr.port()
    );
    assert_eq!(
        u16::from_be_bytes(first_tcp[2..4].try_into().unwrap()),
        listener_addr.port()
    );
    assert_eq!(tcp_payload(request_packet), b"proxy request");
    assert_eq!(
        u16::from_be_bytes(second_tcp[..2].try_into().unwrap()),
        listener_addr.port()
    );
    assert_eq!(
        u16::from_be_bytes(second_tcp[2..4].try_into().unwrap()),
        client_addr.port()
    );
    assert_eq!(tcp_payload(response_packet), b"proxy response");
    let report = read_report(&path, 10, None).unwrap();
    let captured_packets: Vec<_> = report
        .packets
        .iter()
        .filter(|packet| {
            packet.payload_text.contains("proxy request")
                || packet.payload_text.contains("proxy response")
        })
        .collect();
    assert_eq!(captured_packets.len(), 2);
    assert_eq!(captured_packets[0].proxy_protocol.as_deref(), Some("HTTP"));
    assert_eq!(captured_packets[0].direction, "upload");
    assert_eq!(captured_packets[1].proxy_protocol.as_deref(), Some("HTTP"));
    assert_eq!(captured_packets[1].direction, "download");
    fs::remove_file(path).unwrap();
}
