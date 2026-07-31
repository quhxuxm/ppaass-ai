use super::*;

#[tokio::test]
async fn initializes_key_encryption_binding_for_empty_database() {
    let (_directory, store) = test_store().await;
    let binding = store.key_encryption_binding().await.unwrap();
    assert!(binding.verifier.is_none());
    assert!(binding.sample_private_key.is_none());

    assert_eq!(
        store
            .initialize_key_encryption_verifier("empty-database-verifier")
            .await
            .unwrap(),
        "empty-database-verifier"
    );
    let binding = store.key_encryption_binding().await.unwrap();
    assert_eq!(binding.verifier.as_deref(), Some("empty-database-verifier"));
    assert!(binding.sample_private_key.is_none());
}

#[tokio::test]
async fn initializes_key_encryption_binding_for_legacy_only_database() {
    let (_directory, store) = test_store().await;
    store
        .create_user_record(NewUser::new(
            "legacy-user",
            public_key(),
            UserOrigin::Legacy,
        ))
        .await
        .unwrap();

    let binding = store.key_encryption_binding().await.unwrap();
    assert!(binding.verifier.is_none());
    assert!(binding.sample_private_key.is_none());
    assert_eq!(
        store
            .initialize_key_encryption_verifier("legacy-database-verifier")
            .await
            .unwrap(),
        "legacy-database-verifier"
    );
    let binding = store.key_encryption_binding().await.unwrap();
    assert_eq!(
        binding.verifier.as_deref(),
        Some("legacy-database-verifier")
    );
    assert!(binding.sample_private_key.is_none());
}

#[tokio::test]
async fn key_encryption_binding_returns_existing_encrypted_sample() {
    let (_directory, store) = test_store().await;
    store
        .create_managed_user(managed_user(
            "account-alice",
            "alice-login",
            "alice",
            AccountRole::User,
            None,
        ))
        .await
        .unwrap();
    store
        .initialize_key_encryption_verifier("managed-database-verifier")
        .await
        .unwrap();

    let binding = store.key_encryption_binding().await.unwrap();
    assert_eq!(
        binding.verifier.as_deref(),
        Some("managed-database-verifier")
    );
    let sample = binding.sample_private_key.unwrap();
    assert_eq!(sample.username, "alice");
    assert_eq!(
        sample.encrypted_private_key,
        b"encrypted-private-key".to_vec()
    );
    assert_eq!(sample.key_version, 1);
    assert!(sample.updated_at > 0);
}

#[tokio::test]
async fn concurrent_and_repeated_key_encryption_initialization_never_overwrites() {
    let (_directory, store) = test_store().await;
    let (first, second) = tokio::join!(
        store.initialize_key_encryption_verifier("concurrent-verifier-a"),
        store.initialize_key_encryption_verifier("concurrent-verifier-b"),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first, second);
    assert!(
        first == "concurrent-verifier-a" || first == "concurrent-verifier-b",
        "并发初始化必须保留其中一个调用方的 verifier"
    );

    assert_eq!(
        store
            .initialize_key_encryption_verifier("replacement-verifier")
            .await
            .unwrap(),
        first
    );
    assert_eq!(
        store
            .key_encryption_binding()
            .await
            .unwrap()
            .verifier
            .as_deref(),
        Some(first.as_str())
    );
    let metadata_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_metadata WHERE key = ?")
        .bind(KEY_ENCRYPTION_VERIFIER_KEY)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(metadata_rows, 1);
}
