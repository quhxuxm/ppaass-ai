use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn first_write_opens_flow_with_data_and_later_writes_use_data() {
    let (command_tx, mut command_rx) = mpsc::channel(2);
    let (_inbound_tx, inbound_rx) = mpsc::channel(1);
    let address = Address::Ipv4 {
        addr: [127, 0, 0, 1],
        port: 53,
    };
    let mut stream = UdpClientStream {
        flow_id: 7,
        open_address: Some(address.clone()),
        stream_id: "test-stream".to_string(),
        command_tx: PollSender::new(command_tx),
        inbound_rx,
        read_buf: Vec::new(),
        read_pos: 0,
        close_sent: false,
    };

    stream.write_all(b"first").await.unwrap();
    match command_rx.recv().await.unwrap() {
        ClientCommand::OpenData {
            flow_id,
            address: actual_address,
            data,
        } => {
            assert_eq!(flow_id, 7);
            assert_eq!(actual_address, address);
            assert_eq!(data, b"first");
        }
        _ => panic!("first write did not open the UDP flow"),
    }

    stream.write_all(b"second").await.unwrap();
    match command_rx.recv().await.unwrap() {
        ClientCommand::Data { flow_id, data } => {
            assert_eq!(flow_id, 7);
            assert_eq!(data, b"second");
        }
        _ => panic!("later write did not use UDP flow data"),
    }
}

#[tokio::test]
async fn stream_rejects_short_read_buffer_without_splitting_datagram() {
    let (command_tx, _command_rx) = mpsc::channel(1);
    let (inbound_tx, inbound_rx) = mpsc::channel(1);
    let mut stream = UdpClientStream {
        flow_id: 1,
        open_address: None,
        stream_id: "test-stream".to_string(),
        command_tx: PollSender::new(command_tx),
        inbound_rx,
        read_buf: Vec::new(),
        read_pos: 0,
        close_sent: false,
    };
    inbound_tx.send(vec![1, 2, 3, 4]).await.unwrap();

    let mut short = [0u8; 3];
    let error = stream.read(&mut short).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(short, [0; 3]);

    let mut exact = [0u8; 4];
    assert_eq!(stream.read(&mut exact).await.unwrap(), 4);
    assert_eq!(exact, [1, 2, 3, 4]);
}
