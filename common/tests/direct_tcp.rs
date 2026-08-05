use common::direct_tcp::{connect_tcp_addresses_happy_eyeballs, interleave_address_families};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::Instant;

#[test]
fn address_families_are_interleaved_without_reordering_each_family() {
    let addresses = vec![
        "[2001:db8::1]:443".parse().unwrap(),
        "[2001:db8::2]:443".parse().unwrap(),
        "192.0.2.1:443".parse().unwrap(),
        "192.0.2.2:443".parse().unwrap(),
    ];

    assert_eq!(
        interleave_address_families(addresses),
        vec![
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
        ]
    );
}

#[tokio::test]
async fn fast_failure_starts_next_candidate_without_fallback_delay() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reachable = listener.local_addr().unwrap();
    let refused = SocketAddr::new(reachable.ip(), reachable.port().wrapping_add(1));

    let started = Instant::now();
    let stream = connect_tcp_addresses_happy_eyeballs(vec![refused, reachable], |_, _| Ok(()))
        .await
        .unwrap();

    assert!(started.elapsed() < Duration::from_millis(250));
    drop(stream);
}
