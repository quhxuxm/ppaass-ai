use desktop_agent_be::tun_handler::tls_client_hello_server_name;

fn client_hello_with_sni(host: &str) -> Vec<u8> {
    let host = host.as_bytes();
    let mut hello = vec![3, 3];
    hello.extend([0; 32]);
    hello.push(0);
    hello.extend([0, 2, 0x13, 1]);
    hello.extend([1, 0]);
    let mut server_name = Vec::new();
    server_name.push(0);
    server_name.extend((host.len() as u16).to_be_bytes());
    server_name.extend(host);
    let mut extensions = vec![0, 0];
    extensions.extend(((server_name.len() + 2) as u16).to_be_bytes());
    extensions.extend((server_name.len() as u16).to_be_bytes());
    extensions.extend(server_name);
    extensions.extend([0, 10, 0, 2, 0, 0]);
    hello.extend((extensions.len() as u16).to_be_bytes());
    hello.extend(extensions);
    let mut handshake = vec![1, 0, ((hello.len() >> 8) & 0xff) as u8, hello.len() as u8];
    handshake.extend(hello);
    let mut record = vec![22, 3, 1];
    record.extend((handshake.len() as u16).to_be_bytes());
    record.extend(handshake);
    record
}

#[test]
fn extracts_server_name_from_tls_client_hello() {
    let packet = client_hello_with_sni("chatgpt.com");

    assert_eq!(
        tls_client_hello_server_name(&packet),
        Some("chatgpt.com".to_string())
    );
}

#[test]
fn extracts_server_name_before_the_client_hello_is_complete() {
    let packet = client_hello_with_sni("chatgpt.com");
    let partial_packet = &packet[..packet.len() - 6];

    assert_eq!(
        tls_client_hello_server_name(partial_packet),
        Some("chatgpt.com".to_string())
    );
}

#[test]
fn rejects_non_tls_packets() {
    assert_eq!(tls_client_hello_server_name(b"GET / HTTP/1.1\r\n"), None);
}
