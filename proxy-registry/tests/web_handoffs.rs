use proxy_registry::{
    AccountRepository, AgentWebSessionHandoffConsumeError, AgentWebSessionHandoffIssueError,
    AgentWebSessionHandoffRepository, AgentWebSessionHandoffStore, NewAdminAccount,
    SqliteUserRepository,
};
use std::sync::Arc;
use tempfile::TempDir;

async fn test_store(
    maximum_entries: u32,
    maximum_entries_per_account: u32,
) -> (TempDir, AgentWebSessionHandoffStore) {
    let directory = TempDir::new().unwrap();
    let repository = Arc::new(
        SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
            .await
            .unwrap(),
    );
    repository
        .bootstrap_admin_if_absent(NewAdminAccount {
            account_id: "acc_alice".to_string(),
            login_name: "admin".to_string(),
            password_hash: None,
            display_name: None,
            email: None,
            avatar_url: None,
        })
        .await
        .unwrap();
    let repository: Arc<dyn AgentWebSessionHandoffRepository> = repository;
    (
        directory,
        AgentWebSessionHandoffStore::with_limits(
            repository,
            maximum_entries,
            maximum_entries_per_account,
        ),
    )
}

#[tokio::test]
async fn handoff_is_shared_single_use_and_rejects_tampering_and_expiry() {
    let (_directory, store) = test_store(4, 4).await;
    let issued = store.issue_at("acc_alice", 7, 1_000).await.unwrap();
    let mut tampered = issued.code.clone().into_bytes();
    tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        store
            .consume_at(std::str::from_utf8(&tampered).unwrap(), 1_001)
            .await,
        Err(AgentWebSessionHandoffConsumeError::InvalidOrConsumed)
    );

    let claim = store.consume_at(&issued.code, 1_001).await.unwrap();
    assert_eq!(claim.account_id, "acc_alice");
    assert_eq!(claim.account_auth_version, 7);
    assert_eq!(
        store.consume_at(&issued.code, 1_002).await,
        Err(AgentWebSessionHandoffConsumeError::InvalidOrConsumed)
    );

    let expired = store.issue_at("acc_alice", 7, 2_000).await.unwrap();
    assert_eq!(expired.expires_at, 2_090);
    assert_eq!(
        store.consume_at(&expired.code, expired.expires_at).await,
        Err(AgentWebSessionHandoffConsumeError::Expired)
    );
}

#[tokio::test]
async fn handoff_store_enforces_per_account_capacity_and_prunes_expired_entries() {
    let (_directory, store) = test_store(2, 1).await;
    store.issue_at("acc_alice", 1, 1_000).await.unwrap();
    assert_eq!(
        store.issue_at("acc_alice", 1, 1_001).await.map(|_| ()),
        Err(AgentWebSessionHandoffIssueError::Capacity)
    );
    assert!(store.issue_at("acc_alice", 1, 1_091).await.is_ok());
}
