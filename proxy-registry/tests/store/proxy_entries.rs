use super::*;

fn registration(
    entry_id: &str,
    version: &str,
    advertised_address: &str,
    received_at: i64,
) -> ProxyEntryRegistration {
    ProxyEntryRegistration {
        entry_id: entry_id.to_string(),
        version: version.to_string(),
        advertised_address: advertised_address.to_string(),
        received_at,
    }
}

#[tokio::test]
async fn registration_creates_and_updates_one_enabled_catalog_node() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let writer = SqliteUserRepository::connect(&path).await.unwrap();
    let reader = SqliteUserRepository::connect(&path).await.unwrap();

    writer
        .register_proxy_entry(registration("entry-a", "1.0.0", "A.example:8080", 100))
        .await
        .unwrap();
    let nodes = ProxyAddressRepository::list_proxy_addresses(&reader)
        .await
        .unwrap();
    let node = nodes
        .iter()
        .find(|node| node.entry_id.as_deref() == Some("entry-a"))
        .unwrap();
    assert_eq!(node.label, "entry-a");
    assert_eq!(node.address, "a.example:8080");
    assert!(node.enabled);
    assert_eq!(node.entry_version.as_deref(), Some("1.0.0"));
    assert_eq!(node.entry_first_registered_at, Some(100));
    assert_eq!(node.entry_last_heartbeat_at, Some(100));

    writer
        .register_proxy_entry(registration("entry-a", "1.1.0", "a.example:8080", 130))
        .await
        .unwrap();
    let nodes = ProxyAddressRepository::list_proxy_addresses(&reader)
        .await
        .unwrap();
    assert_eq!(
        nodes.iter().filter(|node| node.entry_id.is_some()).count(),
        1
    );
    let node = nodes
        .iter()
        .find(|node| node.entry_id.as_deref() == Some("entry-a"))
        .unwrap();
    assert_eq!(node.entry_version.as_deref(), Some("1.1.0"));
    assert_eq!(node.entry_first_registered_at, Some(100));
    assert_eq!(node.entry_last_heartbeat_at, Some(130));

    writer
        .register_proxy_entry(registration("entry-a", "1.1.0", "new.example:8443", 160))
        .await
        .unwrap();
    let nodes = ProxyAddressRepository::list_proxy_addresses(&reader)
        .await
        .unwrap();
    let node = nodes
        .iter()
        .find(|node| node.entry_id.as_deref() == Some("entry-a"))
        .unwrap();
    assert_eq!(node.address, "new.example:8443");
    assert_eq!(node.entry_first_registered_at, Some(100));
    assert_eq!(node.entry_last_heartbeat_at, Some(160));
}

#[tokio::test]
async fn registration_binds_an_existing_address_without_overwriting_admin_fields() {
    let (_directory, store) = test_store().await;
    let manual = store
        .create_proxy_address(NewProxyAddress {
            proxy_address_id: "pxy_manual_entry".to_string(),
            label: "管理员节点名称".to_string(),
            address: "entry.example:443".to_string(),
            enabled: false,
        })
        .await
        .unwrap();
    store
        .register_proxy_entry(registration(
            "entry-existing",
            "2.0.0",
            "entry.example:443",
            200,
        ))
        .await
        .unwrap();

    let nodes = ProxyAddressRepository::list_proxy_addresses(&store)
        .await
        .unwrap();
    let bound = nodes
        .iter()
        .find(|node| node.entry_id.as_deref() == Some("entry-existing"))
        .unwrap();
    assert_eq!(bound.proxy_address_id, manual.proxy_address_id);
    assert_eq!(bound.label, "管理员节点名称");
    assert!(!bound.enabled);
}

#[tokio::test]
async fn registration_rejects_an_address_owned_by_another_entry() {
    let directory = TempDir::new().unwrap();
    let store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
        .await
        .unwrap();
    store
        .register_proxy_entry(registration("entry-a", "1.0.0", "a.example:443", 100))
        .await
        .unwrap();
    store
        .register_proxy_entry(registration("entry-b", "1.0.0", "b.example:443", 100))
        .await
        .unwrap();
    let error = store
        .register_proxy_entry(registration("entry-a", "1.0.1", "b.example:443", 130))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        UserRepositoryError::ProxyEntryAddressConflict(_)
    ));
}
