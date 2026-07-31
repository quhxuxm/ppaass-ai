use desktop_agent_ui::packet_capture::*;

mod protocols;
mod proxy;

fn pcap_with_packets(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&4_u16.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&101_u32.to_le_bytes());
    for (index, packet) in packets.iter().enumerate() {
        bytes.extend_from_slice(&(index as u32 + 1).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        bytes.extend_from_slice(packet);
    }
    bytes
}

fn ipv4_tcp_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    flags: u8,
) -> Vec<u8> {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = flags;
    packet
}

fn ipv4_tcp_payload_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0u8; 40 + payload.len()];
    let total_length = packet.len() as u16;
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_length.to_be_bytes());
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..28].copy_from_slice(&sequence.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = 0x18;
    packet[40..].copy_from_slice(payload);
    packet
}
