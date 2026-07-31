use super::*;

#[tokio::test]
async fn v7_migration_removes_deprecated_agent_config_view_permission() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("users.sqlite3");
    let store = SqliteUserRepository::connect(&path).await.unwrap();
    store
        .create_user_record(NewUser::new(
            "permission-migration-user",
            public_key(),
            UserOrigin::Local,
        ))
        .await
        .unwrap();
    sqlx::query("UPDATE users SET permissions = ? WHERE username = ?")
        .bind(
            "agent.config.view,agent.egress.edit,agent.packet_capture,\
             agent.runtime_threads.edit,proxy.connect.tcp,proxy.connect.udp",
        )
        .bind("permission-migration-user")
        .execute(store.pool())
        .await
        .unwrap();
    drop_v12_registry_coordination_tables(&store).await;
    drop_v8_proxy_address_tables(&store).await;
    drop_v11_operation_audits(&store).await;
    drop_v10_account_disable_audits(&store).await;
    drop_v9_key_request_columns(&store).await;
    sqlx::query("PRAGMA user_version = 6")
        .execute(store.pool())
        .await
        .unwrap();
    store.pool().close().await;

    let reopened = SqliteUserRepository::connect(&path).await.unwrap();
    let user = reopened
        .get_user("permission-migration-user")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        user.permissions,
        [
            "agent.egress.edit",
            "agent.packet_capture",
            "agent.runtime_threads.edit",
            "proxy.connect.tcp",
            "proxy.connect.udp",
        ]
    );
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(version, SQLITE_SCHEMA_VERSION);
}
