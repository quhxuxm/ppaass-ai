use super::super::*;
use super::support::{PendingShutdownTarget, ShutdownErrorTarget};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn relay_keeps_target_response_after_agent_half_close() {
    let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
    let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);

    let relay = tokio::spawn(async move {
        relay_tcp_with_half_close(
            &mut target_relay,
            &mut agent_relay,
            TcpRelayTimeouts::from_durations(
                Some(Duration::from_secs(5)),
                Some(Duration::from_secs(5)),
            ),
        )
        .await
    });

    // 模拟 agent 请求方向先结束：这在协议层表现为空 end 包或 TCP FIN。
    // relay 不能因此立即结束，否则目标随后返回的响应体会被截断。
    agent_peer.write_all(b"GET").await.unwrap();
    agent_peer.shutdown().await.unwrap();

    let mut request = [0u8; 3];
    target_peer.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"GET");

    let mut eof_probe = [0u8; 1];
    assert_eq!(target_peer.read(&mut eof_probe).await.unwrap(), 0);

    target_peer.write_all(b"complete-body").await.unwrap();
    target_peer.shutdown().await.unwrap();

    let mut response = Vec::new();
    agent_peer.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"complete-body");

    let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(up_bytes, 3);
    assert_eq!(down_bytes, b"complete-body".len() as u64);
}

#[tokio::test]
async fn relay_keeps_half_close_when_idle_timeout_disabled() {
    let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
    let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);

    let relay = tokio::spawn(async move {
        relay_tcp_with_half_close(
            &mut target_relay,
            &mut agent_relay,
            TcpRelayTimeouts::from_durations(None, None),
        )
        .await
    });

    // timeout=0 的配置现在只表示“不启用超时”，不能再切回旧的
    // copy_bidirectional 路径；半关闭语义必须和启用超时时完全一致。
    agent_peer.write_all(b"GET").await.unwrap();
    agent_peer.shutdown().await.unwrap();

    let mut request = [0u8; 3];
    target_peer.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"GET");

    let mut eof_probe = [0u8; 1];
    assert_eq!(target_peer.read(&mut eof_probe).await.unwrap(), 0);

    target_peer.write_all(b"complete-body").await.unwrap();
    target_peer.shutdown().await.unwrap();

    let mut response = Vec::new();
    agent_peer.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"complete-body");

    let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(up_bytes, 3);
    assert_eq!(down_bytes, b"complete-body".len() as u64);
}

#[tokio::test]
async fn relay_keeps_response_when_request_shutdown_errors() {
    let mut target_relay = ShutdownErrorTarget::new(b"complete-body");
    let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);

    let relay = tokio::spawn(async move {
        relay_tcp_with_half_close(
            &mut target_relay,
            &mut agent_relay,
            TcpRelayTimeouts::from_durations(
                Some(Duration::from_secs(5)),
                Some(Duration::from_secs(5)),
            ),
        )
        .await
    });

    agent_peer.write_all(b"GET").await.unwrap();
    agent_peer.shutdown().await.unwrap();

    let mut response = Vec::new();
    agent_peer.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"complete-body");

    let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(up_bytes, 3);
    assert_eq!(down_bytes, b"complete-body".len() as u64);
}

#[tokio::test]
async fn relay_drains_response_when_request_shutdown_stalls() {
    let mut target_relay = PendingShutdownTarget::new(b"complete-body");
    let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);

    let relay = tokio::spawn(async move {
        relay_tcp_with_half_close(
            &mut target_relay,
            &mut agent_relay,
            TcpRelayTimeouts::from_durations(
                Some(Duration::from_millis(100)),
                Some(Duration::from_millis(100)),
            ),
        )
        .await
    });

    // 模拟目标写半边关闭迟迟不完成：旧的单 select relay 会卡在
    // agent->target 的 shutdown 上，导致 target->agent 已经可读的响应无法排空。
    // 新实现两个方向独立并发，所以下行响应应当先完整写回 agent；剩余挂起方向
    // 再由 idle timeout 回收。
    agent_peer.write_all(b"GET").await.unwrap();
    agent_peer.shutdown().await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        agent_peer.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response, b"complete-body");

    let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(up_bytes, 3);
    assert_eq!(down_bytes, b"complete-body".len() as u64);
}

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

    let mut eof_probe = [0u8; 1];
    assert_eq!(target_peer.read(&mut eof_probe).await.unwrap(), 0);

    let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(up_bytes, 3);
    assert_eq!(down_bytes, 0);

    let mut closed_probe = [0u8; 1];
    assert_eq!(target_peer.read(&mut closed_probe).await.unwrap(), 0);
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
    assert_eq!(&request, b"GET");

    let mut eof_probe = [0u8; 1];
    assert_eq!(target_peer.read(&mut eof_probe).await.unwrap(), 0);

    target_peer.write_all(b"part-1").await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    target_peer.write_all(b"part-2").await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    target_peer.write_all(b"part-3").await.unwrap();
    target_peer.shutdown().await.unwrap();

    let mut response = Vec::new();
    agent_peer.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"part-1part-2part-3");

    let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(up_bytes, 3);
    assert_eq!(down_bytes, b"part-1part-2part-3".len() as u64);
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
    let result = tokio::time::timeout(Duration::from_secs(2), &mut relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.0, 4);
}

#[tokio::test]
async fn relay_activity_does_not_reset_on_flush_without_bytes() {
    let (activity_tx, mut activity_rx) = tokio::sync::watch::channel(());
    activity_rx.borrow_and_update();
    let read_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut sink = tokio::io::sink();
    let mut relay_io = RelayCopyIo::new(
        &mut sink,
        "flush-only",
        activity_tx,
        read_bytes.clone(),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );

    relay_io.flush().await.unwrap();

    assert!(!activity_rx.has_changed().unwrap());
    assert_eq!(read_bytes.load(Ordering::Acquire), 0);
}
