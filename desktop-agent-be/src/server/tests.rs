use super::*;
use crate::config::AgentConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

fn direct_test_resources() -> (
    Arc<YamuxSessionManager>,
    Arc<YamuxSessionManager>,
    Arc<DirectAccessChecker>,
    PacketCaptureController,
) {
    let config: AgentConfig = toml::from_str(
        r#"
listen_addr = "127.0.0.1:10080"
username = "test"
private_key_path = "unused-test-key.pem"

[direct_access]
mode = "direct_all"
"#,
    )
    .unwrap();
    let config = Arc::new(config);
    let proxy_addrs = Arc::new(vec!["127.0.0.1:9".to_string()]);
    (
        Arc::new(YamuxSessionManager::new(
            config.clone(),
            proxy_addrs.clone(),
        )),
        Arc::new(YamuxSessionManager::new_udp(
            config.clone(),
            proxy_addrs,
        )),
        Arc::new(DirectAccessChecker::new(&config.direct_access)),
        PacketCaptureController::new("unused-desktop-http-test.pcap".into()),
    )
}

async fn connect_to_test_proxy() -> (
    TcpStream,
    tokio::task::JoinHandle<Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let (tcp_sessions, udp_sessions, direct_checker, packet_capture) = direct_test_resources();
    let proxy_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        handle_connection(
            stream,
            tcp_sessions,
            udp_sessions,
            direct_checker,
            packet_capture,
        )
        .await
    });
    let client = TcpStream::connect(listen_addr).await.unwrap();
    (client, proxy_task)
}

async fn read_http_head(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
            .await
            .expect("HTTP response head timed out")
            .expect("HTTP response head ended early");
        response.push(byte[0]);
    }
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn windows_shared_listener_supports_regular_http_proxy_requests() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let request = read_http_head(&mut stream).await;
        assert!(
            request.starts_with("GET /desktop-http?probe=1 HTTP/1.1"),
            "{request}"
        );
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nHTTP-OK",
            )
            .await
            .unwrap();
    });

    let (mut client, proxy_task) = connect_to_test_proxy().await;
    client
        .write_all(
            format!(
                "GET http://{origin_addr}/desktop-http?probe=1 HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let mut response = String::new();
    timeout(Duration::from_secs(3), client.read_to_string(&mut response))
        .await
        .expect("regular HTTP proxy response timed out")
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("HTTP-OK"), "{response}");

    origin_task.await.unwrap();
    proxy_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn windows_shared_listener_supports_http_connect_tunnels() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let mut payload = [0_u8; 20];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });

    let (mut client, proxy_task) = connect_to_test_proxy().await;
    client
        .write_all(
            format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let response = read_http_head(&mut client).await;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

    let payload = b"desktop-connect-test";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0_u8; payload.len()];
    timeout(Duration::from_secs(3), client.read_exact(&mut echoed))
        .await
        .expect("CONNECT tunnel response timed out")
        .unwrap();
    assert_eq!(echoed, payload);
    drop(client);

    echo_task.await.unwrap();
    proxy_task.await.unwrap().unwrap();
}
