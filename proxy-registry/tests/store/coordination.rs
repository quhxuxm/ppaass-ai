use super::*;

#[tokio::test]
async fn schema_uses_tables_and_ordinary_sql_without_database_triggers() {
    let (_directory, store) = test_store().await;
    let trigger_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_schema WHERE type = 'trigger'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(trigger_count, 0);

    let mut transaction = store.pool().begin().await.unwrap();
    for table in ["registry_agent_events", "agent_web_session_handoffs"] {
        assert!(
            !table_columns(&mut transaction, table)
                .await
                .unwrap()
                .is_empty()
        );
    }
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn web_session_handoff_can_be_issued_and_consumed_across_repositories_once() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let first = SqliteUserRepository::connect(&path).await.unwrap();
    create_admin(&first, "acc_admin").await;
    let second = SqliteUserRepository::connect(&path).await.unwrap();

    let handoff = NewAgentWebSessionHandoff {
        code_hash: "test-code-hash".to_string(),
        account_id: "acc_admin".to_string(),
        account_auth_version: 7,
        expires_at: 1_090,
    };
    assert_eq!(
        first
            .create_agent_web_session_handoff(handoff, 1_000, 10, 4)
            .await
            .unwrap(),
        AgentWebSessionHandoffCreate::Created
    );
    assert_eq!(
        second
            .consume_agent_web_session_handoff("test-code-hash", 1_001)
            .await
            .unwrap(),
        AgentWebSessionHandoffConsume::Claimed {
            account_id: "acc_admin".to_string(),
            account_auth_version: 7,
        }
    );
    assert_eq!(
        first
            .consume_agent_web_session_handoff("test-code-hash", 1_002)
            .await
            .unwrap(),
        AgentWebSessionHandoffConsume::NotFound
    );
}

#[tokio::test]
async fn purging_agent_events_preserves_the_latest_revision_anchor() {
    let (_directory, store) = test_store().await;
    store
        .create_user("alice", &public_key(), None)
        .await
        .unwrap();
    store.create_user("bob", &public_key(), None).await.unwrap();
    let latest = store.latest_agent_event_revision().await.unwrap();

    let removed = store.purge_agent_events_before(i64::MAX).await.unwrap();
    assert!(removed > 0);
    assert_eq!(store.latest_agent_event_revision().await.unwrap(), latest);
    let remaining = store.list_agent_events_after(0, 100).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].revision, latest);

    assert_eq!(store.purge_agent_events_before(i64::MAX).await.unwrap(), 0);
    assert_eq!(store.latest_agent_event_revision().await.unwrap(), latest);
}
