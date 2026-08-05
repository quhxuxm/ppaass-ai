use proxy_registry::{
    AgentEventHub, NewProxyAddress, ProxyAddressRepository, SqliteUserRepository,
};
use std::{sync::Arc, time::Duration};
use tempfile::TempDir;

#[tokio::test]
async fn independent_registry_hubs_receive_the_same_sqlite_event() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let first_store = Arc::new(SqliteUserRepository::connect(&path).await.unwrap());
    let second_store = Arc::new(SqliteUserRepository::connect(&path).await.unwrap());
    let first_hub = AgentEventHub::start(first_store.clone()).await.unwrap();
    let second_hub = AgentEventHub::start(second_store).await.unwrap();
    let mut first_receiver = first_hub.subscribe();
    let mut second_receiver = second_hub.subscribe();

    first_store
        .create_proxy_address(NewProxyAddress {
            proxy_address_id: "proxy-event-test".to_string(),
            label: "Event test".to_string(),
            address: "127.0.0.1:8080".to_string(),
            enabled: true,
        })
        .await
        .unwrap();

    let first = tokio::time::timeout(Duration::from_secs(2), first_receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(2), second_receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.kind.as_ref(), "admin_key_requests_changed");
    assert!(first.is_visible_to("any-account"));
    assert!(first.revision > 0);
}
