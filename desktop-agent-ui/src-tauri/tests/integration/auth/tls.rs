use std::sync::Arc;

use desktop_agent_ui::auth::{
    build_proxy_registry_client, AgentServerEventKind, AgentServerEventStream,
};
use rcgen::generate_simple_self_signed;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::rustls::{pki_types::PrivatePkcs8KeyDer, ServerConfig};
use tokio_rustls::TlsAcceptor;

async fn spawn_self_signed_https_server(response: Vec<u8>) -> (String, JoinHandle<()>) {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let certified = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let private_key = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], private_key.into())
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0, "TLS request ended before its headers");
            request.extend_from_slice(&buffer[..read]);
        }
        stream.write_all(&response).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    // The certificate is valid only for localhost while the client connects by IP. This proves
    // the Registry policy skips both chain trust and hostname validation.
    (format!("https://127.0.0.1:{}", address.port()), task)
}

#[tokio::test]
async fn ordinary_registry_client_accepts_an_invalid_chain_and_hostname() {
    let body = "registry-ready";
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let (base_url, server) = spawn_self_signed_https_server(response.into_bytes()).await;

    let received = build_proxy_registry_client()
        .unwrap()
        .get(format!("{base_url}/healthz"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(received, body);
    server.await.unwrap();
}

#[tokio::test]
async fn registry_sse_client_accepts_an_invalid_chain_and_hostname() {
    let response = b"HTTP/1.1 200 OK\r\n\
        content-type: text/event-stream\r\n\
        connection: close\r\n\r\n\
        event: sync\r\ndata: {}\r\n\r\n";
    let (base_url, server) = spawn_self_signed_https_server(response.to_vec()).await;

    let mut stream = AgentServerEventStream::connect(&base_url, "test-token")
        .await
        .unwrap();

    assert_eq!(
        stream.next_event().await.unwrap(),
        Some(AgentServerEventKind::Sync)
    );
    server.await.unwrap();
}
