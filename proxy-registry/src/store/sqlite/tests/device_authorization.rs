use super::*;

#[tokio::test]
async fn device_authorization_is_rate_limited_and_finalized_exactly_once() {
    let (_directory, store) = test_store().await;
    let managed = store
        .create_managed_user(managed_user(
            "device-account",
            "device-user",
            "device-user",
            AccountRole::User,
            None,
        ))
        .await
        .unwrap();
    let account = managed.account.unwrap();
    let profile = managed.profile.unwrap();
    let device_code_hash = "A".repeat(43);
    let user_code_hash = "B".repeat(43);
    store
        .create_agent_device_authorization(NewAgentDeviceAuthorization {
            device_code_hash: device_code_hash.clone(),
            user_code_hash: user_code_hash.clone(),
            client_name: "Alice Android".to_string(),
            platform: "android".to_string(),
            created_at: 100,
            expires_at: 700,
        })
        .await
        .unwrap();
    let record = store
        .get_agent_device_authorization_by_user_code(&user_code_hash, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, AgentDeviceAuthorizationStatus::Pending);
    assert_eq!(record.client_name, "Alice Android");

    assert_eq!(
        store
            .poll_agent_device_authorization(&device_code_hash, 101, 5)
            .await
            .unwrap(),
        AgentDeviceAuthorizationPoll::Pending {
            retry_after_seconds: 5
        }
    );
    assert_eq!(
        store
            .poll_agent_device_authorization(&device_code_hash, 102, 5)
            .await
            .unwrap(),
        AgentDeviceAuthorizationPoll::SlowDown {
            retry_after_seconds: 4
        }
    );
    assert_eq!(
        store
            .authorize_agent_device(
                &user_code_hash,
                &account.account_id,
                account.auth_version,
                103,
            )
            .await
            .unwrap(),
        AgentDeviceAuthorizationDecision::Authorized
    );
    assert_eq!(
        store
            .authorize_agent_device(
                &user_code_hash,
                &account.account_id,
                account.auth_version,
                104,
            )
            .await
            .unwrap(),
        AgentDeviceAuthorizationDecision::AlreadyAuthorized
    );

    let first_poll = store
        .poll_agent_device_authorization(&device_code_hash, 105, 5)
        .await
        .unwrap();
    let second_poll = store
        .poll_agent_device_authorization(&device_code_hash, 105, 5)
        .await
        .unwrap();
    assert!(matches!(
        first_poll,
        AgentDeviceAuthorizationPoll::Authorized { .. }
    ));
    assert!(matches!(
        second_poll,
        AgentDeviceAuthorizationPoll::Authorized { .. }
    ));

    let claim = || AgentDeviceAuthorizationClaim {
        device_code_hash: device_code_hash.clone(),
        account_id: account.account_id.clone(),
        account_auth_version: account.auth_version,
        username: profile.username.clone(),
        permissions: profile.permissions.clone(),
        key_version: profile.key_version,
        expires_at: profile.expires_at,
        now: 106,
    };
    let first = store.clone();
    let first_claim = claim();
    let second = store.clone();
    let second_claim = claim();
    let (left, right) = tokio::join!(
        async move {
            first
                .finalize_agent_device_authorization(first_claim)
                .await
                .unwrap()
        },
        async move {
            second
                .finalize_agent_device_authorization(second_claim)
                .await
                .unwrap()
        }
    );
    assert!(
        matches!(
            (&left, &right),
            (
                AgentDeviceAuthorizationFinalize::Finalized,
                AgentDeviceAuthorizationFinalize::AlreadyFinalized
            ) | (
                AgentDeviceAuthorizationFinalize::AlreadyFinalized,
                AgentDeviceAuthorizationFinalize::Finalized
            )
        ),
        "并发领取必须只执行一次状态 CAS"
    );
    assert!(matches!(
        store
            .poll_agent_device_authorization(&device_code_hash, 107, 5)
            .await
            .unwrap(),
        AgentDeviceAuthorizationPoll::Consumed
    ));
}

#[tokio::test]
async fn device_authorization_maintenance_is_time_controlled_and_infrequent() {
    let (_directory, store) = test_store().await;
    sqlx::query(
        "INSERT INTO agent_device_authorizations \
         (device_code_hash, user_code_hash, client_name, platform, status, \
          created_at, expires_at) \
         VALUES (?, ?, 'Old Agent', 'android', 'pending', 1, 100)",
    )
    .bind("O".repeat(43))
    .bind("P".repeat(43))
    .execute(&store.pool)
    .await
    .unwrap();

    for (suffix, now) in [("A", 100_000_i64), ("B", 100_001_i64)] {
        store
            .create_agent_device_authorization(NewAgentDeviceAuthorization {
                device_code_hash: suffix.repeat(43),
                user_code_hash: suffix.to_ascii_lowercase().repeat(43),
                client_name: "Maintenance Test".to_string(),
                platform: "android".to_string(),
                created_at: now,
                expires_at: now + 600,
            })
            .await
            .unwrap();
    }
    let old_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM agent_device_authorizations \
         WHERE device_code_hash = ?)",
    )
    .bind("O".repeat(43))
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert!(!old_exists);
    let maintenance = store.device_authorization_maintenance.lock().await;
    assert_eq!(maintenance.next_run_at, 100_030);
    assert_eq!(maintenance.active_count, 2);
}

#[tokio::test]
async fn concurrent_device_authorization_creation_keeps_cached_capacity_consistent() {
    let (_directory, store) = test_store().await;
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..64_u32 {
        let store = store.clone();
        tasks.spawn(async move {
            store
                .create_agent_device_authorization(NewAgentDeviceAuthorization {
                    device_code_hash: format!("D{index:042}"),
                    user_code_hash: format!("U{index:042}"),
                    client_name: "Concurrent Agent".to_string(),
                    platform: "windows".to_string(),
                    created_at: 200_000,
                    expires_at: 200_600,
                })
                .await
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap().unwrap();
    }
    let database_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_device_authorizations")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(database_count, 64);
    assert_eq!(
        store
            .device_authorization_maintenance
            .lock()
            .await
            .active_count,
        64
    );
}
