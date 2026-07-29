use super::*;
use std::cell::Cell;
use std::fs;
use std::io::Cursor;
use std::rc::Rc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn capture_runtime_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn temporary_capture_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ppaass-android-{label}-{}-{}.pcap",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn pcap_bytes(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = global_header().to_vec();
    for (index, packet) in packets.iter().enumerate() {
        bytes.extend_from_slice(&(index as u32 + 1).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        bytes.extend_from_slice(packet);
    }
    bytes
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

fn tcp_sequence(packet: &[u8]) -> u32 {
    let ip_header_len = match packet[0] >> 4 {
        4 => usize::from(packet[0] & 0x0f) * 4,
        6 => IPV6_HEADER_LEN,
        version => panic!("unexpected IP version {version}"),
    };
    u32::from_be_bytes(
        packet[ip_header_len + 4..ip_header_len + 8]
            .try_into()
            .unwrap(),
    )
}

fn report_for_packets(
    label: &str,
    packets: &[Vec<u8>],
    limit: usize,
    listen_port: Option<u16>,
) -> CaptureReport {
    let path = temporary_capture_path(label);
    fs::write(&path, pcap_bytes(packets)).unwrap();
    let report = read_report(&path, limit, listen_port).unwrap();
    fs::remove_file(path).unwrap();
    report
}

mod analysis;
mod report;
mod writer;
