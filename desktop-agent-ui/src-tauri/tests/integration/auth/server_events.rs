use desktop_agent_ui::auth::{AgentServerEventKind, AgentServerEventStream, SseDecoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn decoder_handles_chunk_boundaries_comments_and_crlf() {
    let mut decoder = SseDecoder::default();
    decoder.push(b": keep-alive\r\neve").unwrap();
    assert_eq!(decoder.next_event().unwrap(), None);
    decoder
        .push(b"nt: profile_changed\r\ndata: {}\r\n\r\n")
        .unwrap();
    assert_eq!(
        decoder.next_event().unwrap(),
        Some(AgentServerEventKind::ProfileChanged)
    );
}

#[test]
fn decoder_ignores_unknown_events() {
    let mut decoder = SseDecoder::default();
    decoder.push(b"event: future_event\n\n").unwrap();
    assert_eq!(decoder.next_event().unwrap(), None);
}

#[tokio::test]
async fn stream_connects_directly_and_reads_initial_sync() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let read = socket.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("authorization: Bearer test-token"));
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  Connection: close\r\n\r\n\
                  event: sync\r\ndata: {}\r\n\r\n",
            )
            .await
            .unwrap();
    });

    let mut stream = AgentServerEventStream::connect(&format!("http://{address}"), "test-token")
        .await
        .unwrap();
    assert_eq!(
        stream.next_event().await.unwrap(),
        Some(AgentServerEventKind::Sync)
    );
    server.await.unwrap();
}
