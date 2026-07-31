use desktop_agent_be::tun_handler::packet_capture::*;
use std::io;
use std::io::Write;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, fs::OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn temporary_capture_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ppaass-{label}-{}-{}.pcap",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn read_pcap_packets(bytes: &[u8]) -> Vec<&[u8]> {
    let mut packets = Vec::new();
    let mut offset = 24usize;
    while offset + 16 <= bytes.len() {
        let captured_len =
            u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
        let packet_start = offset + 16;
        let packet_end = packet_start + captured_len;
        if packet_end > bytes.len() {
            break;
        }
        packets.push(&bytes[packet_start..packet_end]);
        offset = packet_end;
    }
    packets
}

fn tcp_payload(packet: &[u8]) -> &[u8] {
    let ip_header_len = match packet[0] >> 4 {
        4 => usize::from(packet[0] & 0x0f) * 4,
        6 => IPV6_HEADER_LEN,
        version => panic!("unexpected IP version {version}"),
    };
    let tcp = &packet[ip_header_len..];
    let tcp_header_len = usize::from(tcp[12] >> 4) * 4;
    &tcp[tcp_header_len..]
}

#[test]
fn asynchronously_writes_raw_ip_pcap_header_and_packet() {
    let path = temporary_capture_path("packet-capture");
    let capture = PacketCapture::create(&path).unwrap();
    capture.record(&[0x45, 0, 0, 20]).unwrap();
    drop(capture);

    let bytes = fs::read(&path).unwrap();
    fs::remove_file(path).unwrap();
    assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 101);
    assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), 4);
    assert_eq!(u32::from_le_bytes(bytes[36..40].try_into().unwrap()), 4);
    assert_eq!(&bytes[40..], &[0x45, 0, 0, 20]);
}

#[test]
fn full_queue_drops_capture_copy_without_blocking_or_error() {
    let (sender, _receiver) = mpsc::sync_channel(1);
    let capture = PacketCapture::from_sender(sender);

    capture.record(&[0x45]).unwrap();
    capture.record(&[0x45]).unwrap();

    assert_eq!(capture.dropped_packets(), 1);
}

#[test]
fn controller_defaults_off_and_can_toggle_and_clear_without_restart() {
    let path = temporary_capture_path("packet-capture-controller");
    let controller = PacketCaptureController::new(path.clone());

    assert!(!controller.is_enabled());
    controller.record(&[0x45, 0, 0, 20]).unwrap();
    assert!(!path.exists());

    controller.set_enabled(true).unwrap();
    assert!(controller.is_enabled());
    controller.record(&[0x45, 0, 0, 20]).unwrap();
    controller.clear().unwrap();
    assert!(controller.is_enabled());

    controller.set_enabled(false).unwrap();
    assert!(!controller.is_enabled());
    assert_eq!(fs::metadata(&path).unwrap().len(), 24);
    fs::remove_file(path).unwrap();
}

#[test]
fn enabling_capture_appends_to_existing_pcap_until_explicitly_cleared() {
    let path = temporary_capture_path("packet-capture-append");
    let controller = PacketCaptureController::new(path.clone());

    controller.set_enabled(true).unwrap();
    controller.record(&[0x45, 0, 0, 20]).unwrap();
    controller.set_enabled(false).unwrap();
    let first_length = fs::metadata(&path).unwrap().len();

    controller.set_enabled(true).unwrap();
    controller.record(&[0x45, 0, 0, 20]).unwrap();
    controller.set_enabled(false).unwrap();

    let bytes = fs::read(&path).unwrap();
    assert!(bytes.len() as u64 > first_length);
    assert_eq!(read_pcap_packets(&bytes).len(), 2);

    controller.clear().unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), 24);
    fs::remove_file(path).unwrap();
}

#[test]
fn enabling_capture_repairs_an_incomplete_pcap_tail_before_appending() {
    let path = temporary_capture_path("packet-capture-repair-tail");
    let controller = PacketCaptureController::new(path.clone());

    controller.set_enabled(true).unwrap();
    controller.record(&[0x45, 0, 0, 20]).unwrap();
    controller.set_enabled(false).unwrap();

    let mut partial_record = [0u8; 19];
    partial_record[8..12].copy_from_slice(&10u32.to_le_bytes());
    partial_record[12..16].copy_from_slice(&10u32.to_le_bytes());
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&partial_record)
        .unwrap();

    controller.set_enabled(true).unwrap();
    controller.record(&[0x45, 0, 0, 21]).unwrap();
    controller.set_enabled(false).unwrap();

    let bytes = fs::read(&path).unwrap();
    let packets = read_pcap_packets(&bytes);
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0], [0x45, 0, 0, 20]);
    assert_eq!(packets[1], [0x45, 0, 0, 21]);
    fs::remove_file(path).unwrap();
}

#[test]
fn enabling_capture_preserves_an_incompatible_existing_file() {
    let path = temporary_capture_path("packet-capture-incompatible");
    let original = b"not a compatible pcap";
    fs::write(&path, original).unwrap();
    let controller = PacketCaptureController::new(path.clone());

    let error = controller.set_enabled(true).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(!controller.is_enabled());
    fs::remove_file(path).unwrap();
}

#[test]
fn enabling_capture_preserves_a_structurally_invalid_record_and_following_data() {
    let path = temporary_capture_path("packet-capture-invalid-record");
    let mut original = global_header().to_vec();
    let mut invalid_record = [0u8; 16];
    invalid_record[8..12].copy_from_slice(&(PCAP_SNAPLEN + 1).to_le_bytes());
    invalid_record[12..16].copy_from_slice(&(PCAP_SNAPLEN + 1).to_le_bytes());
    original.extend_from_slice(&invalid_record);
    original.extend_from_slice(b"following data must remain");
    fs::write(&path, &original).unwrap();
    let controller = PacketCaptureController::new(path.clone());

    let error = controller.set_enabled(true).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(!controller.is_enabled());
    fs::remove_file(path).unwrap();
}

#[test]
fn synthetic_tcp_and_udp_packets_have_valid_headers_and_checksums() {
    let tcp_source: SocketAddr = "127.0.0.1:51000".parse().unwrap();
    let tcp_destination: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let tcp_packet = synthetic_tcp_packet(tcp_source, tcp_destination, 7, 11, b"GET", 42);
    assert_eq!(tcp_packet[0] >> 4, 4);
    assert_eq!(tcp_packet[9], 6);
    assert_eq!(
        u16::from_be_bytes(tcp_packet[2..4].try_into().unwrap()) as usize,
        tcp_packet.len()
    );
    assert_eq!(internet_checksum(&[&tcp_packet[..IPV4_HEADER_LEN]]), 0);
    let tcp = &tcp_packet[IPV4_HEADER_LEN..];
    let source_ip = [127, 0, 0, 1];
    let destination_ip = [127, 0, 0, 1];
    let tcp_len = (tcp.len() as u16).to_be_bytes();
    assert_eq!(
        internet_checksum(&[&source_ip, &destination_ip, &[0, 6], &tcp_len, tcp]),
        0
    );
    assert_eq!(u16::from_be_bytes(tcp[..2].try_into().unwrap()), 51000);
    assert_eq!(u16::from_be_bytes(tcp[2..4].try_into().unwrap()), 1080);
    assert_eq!(u32::from_be_bytes(tcp[4..8].try_into().unwrap()), 7);
    assert_eq!(tcp_payload(&tcp_packet), b"GET");

    let udp_source: SocketAddr = "[::1]:52000".parse().unwrap();
    let udp_destination: SocketAddr = "[::1]:53000".parse().unwrap();
    let udp_packet = synthetic_udp_packet(udp_source, udp_destination, b"dns", 43);
    assert_eq!(udp_packet[0] >> 4, 6);
    assert_eq!(udp_packet[6], 17);
    let udp = &udp_packet[IPV6_HEADER_LEN..];
    let source_ip = Ipv6Addr::LOCALHOST.octets();
    let destination_ip = Ipv6Addr::LOCALHOST.octets();
    let udp_len = (udp.len() as u32).to_be_bytes();
    assert_eq!(
        internet_checksum(&[&source_ip, &destination_ip, &udp_len, &[0, 0, 0, 17], udp]),
        0
    );
    assert_eq!(&udp[UDP_HEADER_LEN..], b"dns");
}

#[test]
fn synthetic_tcp_capture_splits_large_payload_with_contiguous_sequences() {
    let path = temporary_capture_path("packet-capture-split");
    let controller = PacketCaptureController::new(path.clone());
    controller.set_enabled(true).unwrap();
    let mut flow = TcpCaptureFlow::new(
        controller.clone(),
        "127.0.0.1:51000".parse().unwrap(),
        "127.0.0.1:1080".parse().unwrap(),
    );
    let payload = vec![0x5a; MAX_SYNTHETIC_TCP_PAYLOAD + 17];
    flow.record_client_to_server(&payload);
    controller.set_enabled(false).unwrap();

    let bytes = fs::read(&path).unwrap();
    let packets = read_pcap_packets(&bytes);
    assert_eq!(packets.len(), 2);
    let first_tcp = &packets[0][IPV4_HEADER_LEN..];
    let second_tcp = &packets[1][IPV4_HEADER_LEN..];
    assert_eq!(u32::from_be_bytes(first_tcp[4..8].try_into().unwrap()), 1);
    assert_eq!(
        u32::from_be_bytes(second_tcp[4..8].try_into().unwrap()),
        1 + MAX_SYNTHETIC_TCP_PAYLOAD as u32
    );
    assert_eq!(tcp_payload(packets[0]).len(), MAX_SYNTHETIC_TCP_PAYLOAD);
    assert_eq!(tcp_payload(packets[1]).len(), 17);
    fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn captured_tcp_stream_records_both_directions_without_changing_io() {
    let path = temporary_capture_path("packet-capture-proxy-stream");
    let controller = PacketCaptureController::new(path.clone());
    controller.set_enabled(true).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let mut captured = controller.capture_tcp_stream(server);

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
    controller.set_enabled(false).unwrap();

    let bytes = fs::read(&path).unwrap();
    let packets = read_pcap_packets(&bytes);
    assert_eq!(packets.len(), 2);
    let first_tcp = &packets[0][IPV4_HEADER_LEN..];
    let second_tcp = &packets[1][IPV4_HEADER_LEN..];
    assert_eq!(
        u16::from_be_bytes(first_tcp[..2].try_into().unwrap()),
        client_addr.port()
    );
    assert_eq!(
        u16::from_be_bytes(first_tcp[2..4].try_into().unwrap()),
        listener_addr.port()
    );
    assert_eq!(tcp_payload(packets[0]), b"proxy request");
    assert_eq!(
        u16::from_be_bytes(second_tcp[..2].try_into().unwrap()),
        listener_addr.port()
    );
    assert_eq!(
        u16::from_be_bytes(second_tcp[2..4].try_into().unwrap()),
        client_addr.port()
    );
    assert_eq!(tcp_payload(packets[1]), b"proxy response");
    fs::remove_file(path).unwrap();
}
