use common::UdpSessionSlot;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

#[tokio::test]
async fn slot_initialization_is_singleflight_without_holding_the_mutex() {
    let slot = Arc::new(UdpSessionSlot::new());
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();

    for _ in 0..16 {
        let slot = slot.clone();
        let attempts = attempts.clone();
        tasks.push(tokio::spawn(async move {
            slot.get_or_initialize(
                |_| true,
                move || {
                    let attempts = attempts.clone();
                    async move {
                        attempts.fetch_add(1, Ordering::AcqRel);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Ok::<_, std::io::Error>(7_usize)
                    }
                },
            )
            .await
            .unwrap()
        }));
    }

    for task in tasks {
        assert_eq!(task.await.unwrap(), 7);
    }
    assert_eq!(attempts.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn canceled_initializer_waiter_does_not_stall_the_slot() {
    let slot = Arc::new(UdpSessionSlot::new());
    let started = Arc::new(Notify::new());
    let attempts = Arc::new(AtomicUsize::new(0));
    let initializing_slot = slot.clone();
    let initializing_started = started.clone();
    let initializing_attempts = attempts.clone();
    let initializing_task = tokio::spawn(async move {
        initializing_slot
            .get_or_initialize(
                |_| true,
                move || async move {
                    initializing_attempts.fetch_add(1, Ordering::AcqRel);
                    initializing_started.notify_one();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok::<_, std::io::Error>(11_usize)
                },
            )
            .await
    });
    started.notified().await;
    initializing_task.abort();

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        slot.get_or_initialize(|_| true, || async { Ok::<_, std::io::Error>(12_usize) }),
    )
    .await
    .expect("canceled waiter must not leave the slot initializing")
    .unwrap();

    assert_eq!(result, 11);
    assert_eq!(attempts.load(Ordering::Acquire), 1);
}
