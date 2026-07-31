use common::ClientStream;
use futures::{FutureExt, StreamExt};
use protocol::{
    AgentCodec, CipherState, DataPacket, ProxyCodec, ProxyRequest,
    tcp_transport::{TcpSessionCipher, TcpSessionRole},
};
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio_util::codec::Framed;

fn stream_pair() -> (ClientStream<DuplexStream>, Framed<DuplexStream, ProxyCodec>) {
    let (client_io, proxy_io) = tokio::io::duplex(4096);
    let client_state = Arc::new(CipherState::new());
    let proxy_state = Arc::new(CipherState::new());
    let session_inputs = ([1; 32], [2; 32], [3; 32], [4; 32], [5; 16]);
    client_state
        .set_session_cipher(Arc::new(
            TcpSessionCipher::new(
                TcpSessionRole::Agent,
                session_inputs.0,
                session_inputs.1,
                session_inputs.2,
                session_inputs.3,
                session_inputs.4,
            )
            .unwrap(),
        ))
        .unwrap();
    proxy_state
        .set_session_cipher(Arc::new(
            TcpSessionCipher::new(
                TcpSessionRole::Proxy,
                session_inputs.0,
                session_inputs.1,
                session_inputs.2,
                session_inputs.3,
                session_inputs.4,
            )
            .unwrap(),
        ))
        .unwrap();

    let framed = Framed::new(client_io, AgentCodec::new(client_state));
    let (writer, reader) = futures::StreamExt::split(framed);
    let client = ClientStream {
        writer,
        reader,
        end_sent: false,
        stream_id: "test-stream".to_string(),
        read_buf: Vec::new(),
        read_pos: 0,
    };
    let proxy = Framed::new(proxy_io, ProxyCodec::new(proxy_state));
    (client, proxy)
}

async fn next_data(proxy: &mut Framed<DuplexStream, ProxyCodec>) -> DataPacket {
    match proxy.next().await.unwrap().unwrap() {
        ProxyRequest::Data(packet) => packet,
        _ => panic!("expected data packet"),
    }
}

#[tokio::test]
async fn writes_are_buffered_until_explicit_flush() {
    let (mut client, mut proxy) = stream_pair();

    client.write_all(b"first").await.unwrap();
    client.write_all(b"second").await.unwrap();

    assert!(proxy.next().now_or_never().is_none());

    client.flush().await.unwrap();
    let first = next_data(&mut proxy).await;
    let second = next_data(&mut proxy).await;
    assert_eq!(first.stream_id, "test-stream");
    assert_eq!(first.data, b"first");
    assert!(!first.is_end);
    assert_eq!(second.stream_id, "test-stream");
    assert_eq!(second.data, b"second");
    assert!(!second.is_end);
}

#[tokio::test]
async fn shutdown_flushes_buffered_data_and_sends_one_end_packet() {
    let (mut client, mut proxy) = stream_pair();

    client.write_all(b"payload").await.unwrap();
    assert!(proxy.next().now_or_never().is_none());

    client.shutdown().await.unwrap();
    let data = next_data(&mut proxy).await;
    let end = next_data(&mut proxy).await;
    assert_eq!(data.data, b"payload");
    assert!(!data.is_end);
    assert_eq!(end.stream_id, "test-stream");
    assert!(end.data.is_empty());
    assert!(end.is_end);

    client.shutdown().await.unwrap();
    assert!(proxy.next().now_or_never().is_none());
}
