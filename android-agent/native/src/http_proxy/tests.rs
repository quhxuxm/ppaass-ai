use super::*;
use std::time::Duration;

use common::YamuxConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};

use crate::config::{AndroidAgentConfig, AndroidTunConfig};
use crate::direct_access::{DirectAccessConfig, DirectAccessMode};

#[test]
fn proxy_protocol_detection_rejects_non_proxy_probe_bytes() {
    assert_eq!(
        detect_proxy_protocol(0x05),
        Some(ProxyIngressProtocol::Socks5)
    );
    assert_eq!(
        detect_proxy_protocol(b'G'),
        Some(ProxyIngressProtocol::Http)
    );
    assert_eq!(
        detect_proxy_protocol(b'C'),
        Some(ProxyIngressProtocol::Http)
    );
    assert_eq!(detect_proxy_protocol(0), None);
    assert_eq!(detect_proxy_protocol(b'\n'), None);
    assert_eq!(detect_proxy_protocol(b'X'), None);
}

#[test]
fn request_log_host_omits_path_and_query() {
    let uri: Uri = "http://example.com/private/path?access_token=secret"
        .parse()
        .unwrap();

    assert_eq!(request_log_host(&uri), "example.com");
}

#[tokio::test]
async fn socks5_proxy_connects_to_direct_tcp_target() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
    });

    let port_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = port_probe.local_addr().unwrap().port();
    drop(port_probe);

    let shutdown = CancellationToken::new();
    let config = AndroidAgentConfig {
        proxy_addrs: vec!["127.0.0.1:9".to_string()],
        username: "test".to_string(),
        private_key_pem: "test".to_string(),
        proxy_identity_public_key_pem: Some("test".to_string()),
        transport_mode: common::TransportMode::Udp,
        udp_session_pool_size: 4,
        async_runtime_stack_size_mb: 4,
        runtime_threads: 1,
        connect_timeout_secs: 1,
        http_proxy_max_concurrent_connects: 16,
        compression_mode: "none".to_string(),
        yamux: YamuxConfig::default(),
        direct_access: DirectAccessConfig {
            mode: DirectAccessMode::DirectAll,
            rules: Vec::new(),
        },
        tun: AndroidTunConfig::default(),
    };

    let proxy_shutdown = shutdown.clone();
    let proxy_task =
        tokio::spawn(
            async move { run_android_http_proxy(config, proxy_port, proxy_shutdown).await },
        );

    let mut client = None;
    for _ in 0..20 {
        match TcpStream::connect(("127.0.0.1", proxy_port)).await {
            Ok(stream) => {
                client = Some(stream);
                break;
            }
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }
    let mut client = client.expect("SOCKS5 proxy listener should accept connections");

    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [0x05, 0x00]);

    let echo_port = echo_addr.port();
    client
        .write_all(&[
            0x05,
            0x01,
            0x00,
            0x01,
            127,
            0,
            0,
            1,
            (echo_port >> 8) as u8,
            echo_port as u8,
        ])
        .await
        .unwrap();
    let mut connect_reply = [0u8; 10];
    client.read_exact(&mut connect_reply).await.unwrap();
    assert_eq!(&connect_reply[..2], &[0x05, 0x00]);

    let clients = crate::http_proxy_clients::http_proxy_clients_json();
    assert!(
        clients.contains("\"127.0.0.1\""),
        "SOCKS5 client should be visible in proxy client list: {clients}"
    );

    let payload = b"ppaass-socks5-smoke";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    drop(client);
    shutdown.cancel();
    timeout(Duration::from_secs(2), proxy_task)
        .await
        .expect("proxy task should stop")
        .unwrap()
        .unwrap();
    echo_task.await.unwrap();
}

#[tokio::test]
async fn http_proxy_still_supports_regular_http_and_connect() {
    let port_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = port_probe.local_addr().unwrap().port();
    drop(port_probe);

    let shutdown = CancellationToken::new();
    let proxy_shutdown = shutdown.clone();
    let proxy_task = tokio::spawn(async move {
        run_android_http_proxy(test_config(), proxy_port, proxy_shutdown).await
    });

    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin_listener.accept().await.unwrap();
        let request = read_http_head(&mut stream).await;
        assert!(request.starts_with("GET /plain?x=1 HTTP/1.1"), "{request}");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
    });

    let mut http_client = connect_to_proxy(proxy_port).await;
    http_client
        .write_all(
            format!(
                "GET http://{}/plain?x=1 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                origin_addr, origin_addr
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    http_client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("OK"), "{response}");
    origin_task.await.unwrap();

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
    });

    let mut connect_client = connect_to_proxy(proxy_port).await;
    connect_client
        .write_all(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                echo_addr, echo_addr
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let connect_response = read_http_head(&mut connect_client).await;
    assert!(
        connect_response.starts_with("HTTP/1.1 200 OK"),
        "{connect_response}"
    );
    let payload = b"ppaass-http-connect-smoke";
    connect_client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    connect_client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    drop(connect_client);
    echo_task.await.unwrap();

    shutdown.cancel();
    timeout(Duration::from_secs(2), proxy_task)
        .await
        .expect("proxy task should stop")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn http_and_socks5_share_one_port_concurrently() {
    let port_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = port_probe.local_addr().unwrap().port();
    drop(port_probe);

    let shutdown = CancellationToken::new();
    let proxy_shutdown = shutdown.clone();
    let proxy_task = tokio::spawn(async move {
        run_android_http_proxy(test_config(), proxy_port, proxy_shutdown).await
    });

    let slow_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    let (slow_started_tx, slow_started_rx) = oneshot::channel();
    let slow_task = tokio::spawn(async move {
        let (mut stream, _) = slow_listener.accept().await.unwrap();
        let request = read_http_head(&mut stream).await;
        assert!(request.starts_with("GET /slow HTTP/1.1"), "{request}");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n")
            .await
            .unwrap();
        slow_started_tx.send(()).ok();
        stream.write_all(b"slow").await.unwrap();
        sleep(Duration::from_millis(250)).await;
        stream.write_all(b"-socks-body").await.unwrap();
    });

    let mut socks_client = socks5_connect_to_ipv4(proxy_port, slow_addr).await;
    socks_client
        .write_all(b"GET /slow HTTP/1.1\r\nHost: slow.local\r\n\r\n")
        .await
        .unwrap();
    let socks_response = read_http_head(&mut socks_client).await;
    assert!(
        socks_response.starts_with("HTTP/1.1 200 OK"),
        "{socks_response}"
    );
    slow_started_rx
        .await
        .expect("SOCKS5 target should start a long response");

    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin_listener.accept().await.unwrap();
        let request = read_http_head(&mut stream).await;
        assert!(
            request.starts_with("GET /http-while-socks HTTP/1.1"),
            "{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nHTTP-OK")
            .await
            .unwrap();
    });

    let mut http_client = connect_to_proxy(proxy_port).await;
    http_client
        .write_all(
            format!(
                "GET http://{}/http-while-socks HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                origin_addr, origin_addr
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut http_response = String::new();
    http_client
        .read_to_string(&mut http_response)
        .await
        .unwrap();
    assert!(
        http_response.starts_with("HTTP/1.1 200 OK"),
        "{http_response}"
    );
    assert!(http_response.ends_with("HTTP-OK"), "{http_response}");
    origin_task.await.unwrap();

    let mut socks_body = vec![0u8; 15];
    socks_client.read_exact(&mut socks_body).await.unwrap();
    assert_eq!(socks_body, b"slow-socks-body");
    drop(socks_client);
    slow_task.await.unwrap();

    shutdown.cancel();
    timeout(Duration::from_secs(2), proxy_task)
        .await
        .expect("proxy task should stop")
        .unwrap()
        .unwrap();
}

fn test_config() -> AndroidAgentConfig {
    AndroidAgentConfig {
        proxy_addrs: vec!["127.0.0.1:9".to_string()],
        username: "test".to_string(),
        private_key_pem: "test".to_string(),
        proxy_identity_public_key_pem: Some("test".to_string()),
        transport_mode: common::TransportMode::Udp,
        udp_session_pool_size: 4,
        async_runtime_stack_size_mb: 4,
        runtime_threads: 1,
        connect_timeout_secs: 1,
        http_proxy_max_concurrent_connects: 16,
        compression_mode: "none".to_string(),
        yamux: YamuxConfig::default(),
        direct_access: DirectAccessConfig {
            mode: DirectAccessMode::DirectAll,
            rules: Vec::new(),
        },
        tun: AndroidTunConfig::default(),
    }
}

async fn connect_to_proxy(proxy_port: u16) -> TcpStream {
    for _ in 0..20 {
        match TcpStream::connect(("127.0.0.1", proxy_port)).await {
            Ok(stream) => return stream,
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }
    panic!("proxy listener should accept connections");
}

async fn socks5_connect_to_ipv4(proxy_port: u16, target: SocketAddr) -> TcpStream {
    let mut client = connect_to_proxy(proxy_port).await;
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [0x05, 0x00]);

    let ip = match target.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => panic!("test helper only supports IPv4"),
    };
    let port = target.port();
    client
        .write_all(&[
            0x05,
            0x01,
            0x00,
            0x01,
            ip[0],
            ip[1],
            ip[2],
            ip[3],
            (port >> 8) as u8,
            port as u8,
        ])
        .await
        .unwrap();
    let mut connect_reply = [0u8; 10];
    client.read_exact(&mut connect_reply).await.unwrap();
    assert_eq!(&connect_reply[..2], &[0x05, 0x00]);
    client
}

async fn read_http_head(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).await.unwrap();
        bytes.push(buf[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(bytes).unwrap()
}
