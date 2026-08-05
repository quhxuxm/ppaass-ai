use common::client_connection::udp::{
    ClientCommand, prune_closed_udp_streams, udp_client_stream_channel,
};
use protocol::Address;
use std::collections::HashMap;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn first_write_opens_flow_with_data_and_later_writes_use_data() {
    let address = Address::Ipv4 {
        addr: [127, 0, 0, 1],
        port: 53,
    };
    let (mut stream, mut commands, _inbound) =
        udp_client_stream_channel(7, Some(address.clone()), "test-stream".to_string(), 2);

    stream.write_all(b"first").await.unwrap();
    match commands.recv().await.unwrap() {
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
    match commands.recv().await.unwrap() {
        ClientCommand::Data { flow_id, data } => {
            assert_eq!(flow_id, 7);
            assert_eq!(data, b"second");
        }
        _ => panic!("later write did not use UDP flow data"),
    }
}

#[tokio::test]
async fn stream_rejects_short_read_buffer_without_splitting_datagram() {
    let (mut stream, _commands, inbound) =
        udp_client_stream_channel(1, None, "test-stream".to_string(), 1);
    inbound.send(vec![1, 2, 3, 4]).await.unwrap();

    let mut short = [0u8; 3];
    let error = stream.read(&mut short).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(short, [0; 3]);

    let mut exact = [0u8; 4];
    assert_eq!(stream.read(&mut exact).await.unwrap(), 4);
    assert_eq!(exact, [1, 2, 3, 4]);
}

#[tokio::test]
async fn closed_stream_receivers_are_pruned_from_long_lived_session() {
    let (closed_tx, closed_rx) = tokio::sync::mpsc::channel(1);
    let (active_tx, _active_rx) = tokio::sync::mpsc::channel(1);
    drop(closed_rx);
    let mut streams = HashMap::from([(1, closed_tx), (2, active_tx)]);

    assert_eq!(prune_closed_udp_streams(&mut streams), 1);
    assert!(!streams.contains_key(&1));
    assert!(streams.contains_key(&2));
}
