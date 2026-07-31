use proxy_entry::connection::{RelayCopyIo, TcpRelayTimeouts, relay_tcp_with_half_close};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn relay_recycles_idle_persistent_target_after_agent_half_close() {
    let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
    let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);
    let relay = tokio::spawn(async move {
        relay_tcp_with_half_close(
            &mut target_relay,
            &mut agent_relay,
            TcpRelayTimeouts::from_durations(
                Some(Duration::from_secs(30)),
                Some(Duration::from_millis(80)),
            ),
        )
        .await
    });

    agent_peer.write_all(b"GET").await.unwrap();
    agent_peer.shutdown().await.unwrap();
    let mut request = [0u8; 3];
    target_peer.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"GET");
    assert_eq!(target_peer.read(&mut [0u8; 1]).await.unwrap(), 0);

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        (3, 0)
    );
    assert_eq!(target_peer.read(&mut [0u8; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn relay_half_close_idle_keeps_active_slow_response() {
    let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
    let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);
    let relay = tokio::spawn(async move {
        relay_tcp_with_half_close(
            &mut target_relay,
            &mut agent_relay,
            TcpRelayTimeouts::from_durations(
                Some(Duration::from_secs(30)),
                Some(Duration::from_millis(120)),
            ),
        )
        .await
    });

    agent_peer.write_all(b"GET").await.unwrap();
    agent_peer.shutdown().await.unwrap();
    let mut request = [0u8; 3];
    target_peer.read_exact(&mut request).await.unwrap();
    assert_eq!(target_peer.read(&mut [0u8; 1]).await.unwrap(), 0);

    for part in [b"part-1".as_slice(), b"part-2", b"part-3"] {
        target_peer.write_all(part).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    target_peer.shutdown().await.unwrap();
    let mut response = Vec::new();
    agent_peer.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"part-1part-2part-3");
    assert_eq!(relay.await.unwrap().unwrap(), (3, 18));
}

#[tokio::test]
async fn relay_does_not_apply_half_close_timeout_before_eof() {
    let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
    let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);
    let relay = tokio::spawn(async move {
        relay_tcp_with_half_close(
            &mut target_relay,
            &mut agent_relay,
            TcpRelayTimeouts::from_durations(
                Some(Duration::from_millis(300)),
                Some(Duration::from_millis(50)),
            ),
        )
        .await
    });
    tokio::pin!(relay);

    agent_peer.write_all(b"PING").await.unwrap();
    let mut request = [0u8; 4];
    target_peer.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"PING");
    assert!(
        tokio::time::timeout(Duration::from_millis(120), &mut relay)
            .await
            .is_err()
    );

    drop(agent_peer);
    drop(target_peer);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), &mut relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .0,
        4
    );
}

#[tokio::test]
async fn relay_activity_does_not_reset_on_flush_without_bytes() {
    let (activity_tx, mut activity_rx) = tokio::sync::watch::channel(());
    activity_rx.borrow_and_update();
    let read_bytes = Arc::new(AtomicU64::new(0));
    let mut sink = tokio::io::sink();
    let mut relay_io = RelayCopyIo::new(
        &mut sink,
        "flush-only",
        activity_tx,
        read_bytes.clone(),
        Arc::new(AtomicBool::new(false)),
    );

    relay_io.flush().await.unwrap();
    assert!(!activity_rx.has_changed().unwrap());
    assert_eq!(read_bytes.load(Ordering::Acquire), 0);
}
