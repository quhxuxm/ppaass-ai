use super::*;

#[tokio::test]
async fn records_filters_and_purges_access_history() {
    let (_directory, store) = test_store().await;
    store
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();
    store.create_user("bob", &public_key(), None).await.unwrap();
    for record in [
        NewAccessRecord {
            username: "alice".to_string(),
            protocol: AccessProtocol::Tcp,
            target_host: "example.com".to_string(),
            target_port: 443,
            accessed_at: 100,
        },
        NewAccessRecord {
            username: "alice".to_string(),
            protocol: AccessProtocol::Udp,
            target_host: "1.1.1.1".to_string(),
            target_port: 53,
            accessed_at: 101,
        },
        NewAccessRecord {
            username: "alice".to_string(),
            protocol: AccessProtocol::Tcp,
            target_host: "2001:db8::1".to_string(),
            target_port: 8443,
            accessed_at: 102,
        },
        NewAccessRecord {
            username: "bob".to_string(),
            protocol: AccessProtocol::Tcp,
            target_host: "internal.example".to_string(),
            target_port: 80,
            accessed_at: 101,
        },
    ] {
        store.record_access(record).await.unwrap();
    }

    let recent = store.list_recent_access("alice", 101, 10).await.unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].accessed_at, 102);
    assert_eq!(recent[0].target_host, "2001:db8::1");
    assert_eq!(recent[0].access_count, 1);
    assert_eq!(recent[1].protocol, AccessProtocol::Udp);
    assert_eq!(
        store.list_recent_access("alice", 0, 1).await.unwrap().len(),
        1
    );
    assert!(
        store
            .list_recent_access("bob", 102, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        store
            .list_recent_access("alice", 0, MAX_ACCESS_LOG_QUERY_LIMIT + 1)
            .await
            .unwrap_err(),
        UserRepositoryError::Validation(_)
    ));

    assert_eq!(store.purge_access_records_before(102).await.unwrap(), 3);
    let remaining = store.list_recent_access("alice", 0, 10).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].accessed_at, 102);
}

#[tokio::test]
async fn concurrent_accesses_to_the_same_address_increment_one_row() {
    let (directory, store) = test_store().await;
    store
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();
    let second_store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
        .await
        .unwrap();

    let mut writes = Vec::new();
    for offset in 0..32_i64 {
        let repository = if offset % 2 == 0 {
            store.clone()
        } else {
            second_store.clone()
        };
        writes.push(tokio::spawn(async move {
            repository
                .record_access(NewAccessRecord {
                    username: "alice".to_string(),
                    protocol: if offset % 2 == 0 {
                        AccessProtocol::Tcp
                    } else {
                        AccessProtocol::Udp
                    },
                    target_host: if offset % 2 == 0 {
                        "Example.COM".to_string()
                    } else {
                        "example.com".to_string()
                    },
                    target_port: if offset % 2 == 0 { 443 } else { 8443 },
                    accessed_at: 100 + offset,
                })
                .await
                .unwrap();
        }));
    }
    for write in writes {
        write.await.unwrap();
    }

    let records = store.list_recent_access("alice", 0, 10).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target_host, "example.com");
    assert_eq!(records[0].target_port, 8443);
    assert_eq!(records[0].protocol, AccessProtocol::Udp);
    assert_eq!(records[0].accessed_at, 131);
    assert_eq!(records[0].access_count, 32);
}

#[tokio::test]
async fn access_log_retention_defaults_to_seven_and_is_validated_and_persisted() {
    let (directory, store) = test_store().await;
    assert_eq!(
        store.get_access_log_settings().await.unwrap(),
        AccessLogSettings { retention_days: 7 }
    );
    assert_eq!(
        store.set_access_log_retention_days(30).await.unwrap(),
        AccessLogSettings { retention_days: 30 }
    );
    for invalid in [0, MAX_ACCESS_LOG_RETENTION_DAYS + 1] {
        assert!(matches!(
            store
                .set_access_log_retention_days(invalid)
                .await
                .unwrap_err(),
            UserRepositoryError::Validation(_)
        ));
    }
    drop(store);
    let reopened = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
        .await
        .unwrap();
    assert_eq!(
        reopened
            .get_access_log_settings()
            .await
            .unwrap()
            .retention_days,
        30
    );
}
