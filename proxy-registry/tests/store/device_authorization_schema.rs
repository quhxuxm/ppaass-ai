use super::*;

#[tokio::test]
async fn device_authorizations_support_fresh_and_legacy_polling_schemas() {
    let (directory, mut store) = test_store().await;
    let columns: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('agent_device_authorizations')")
            .fetch_all(store.pool())
            .await
            .unwrap();
    assert!(!columns.iter().any(|name| name == "last_polled_at"));

    for legacy_column in [false, true] {
        if legacy_column {
            sqlx::query(
                "ALTER TABLE agent_device_authorizations ADD COLUMN last_polled_at INTEGER",
            )
            .execute(store.pool())
            .await
            .unwrap();
        }
        store.pool().close().await;
        store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
            .await
            .unwrap();
        let code = if legacy_column { "L" } else { "N" }.repeat(43);
        store
            .create_agent_device_authorization(NewAgentDeviceAuthorization {
                device_code_hash: code.clone(),
                user_code_hash: code.clone(),
                client_name: "Schema Test".into(),
                platform: "android".into(),
                created_at: 100,
                expires_at: 700,
            })
            .await
            .unwrap();
        for _ in 0..128 {
            assert_eq!(
                store
                    .poll_agent_device_authorization(&code, 101)
                    .await
                    .unwrap(),
                AgentDeviceAuthorizationPoll::Pending
            );
        }
        assert_eq!(
            store
                .get_agent_device_authorization_by_user_code(&code, 101)
                .await
                .unwrap()
                .unwrap()
                .client_name,
            "Schema Test"
        );
    }
}
