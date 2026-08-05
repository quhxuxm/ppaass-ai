mod support;

use protocol::RsaKeyPair;
use proxy_entry::config::UserConfig;
use proxy_entry::user_manager::{MAX_TCP_AUTH_REPLAY_ENTRIES_PER_USER, UserManager};
use std::sync::Arc;
use support::TestAuthorizationProvider;

#[tokio::test]
async fn observes_authorization_provider_changes() {
    let provider = Arc::new(TestAuthorizationProvider::default());
    let manager = UserManager::new(provider.clone());
    assert!(manager.get_user("alice").await.unwrap().is_none());

    provider
        .set_user(UserConfig {
            username: "alice".to_string(),
            public_key_pem: RsaKeyPair::generate(2048)
                .unwrap()
                .public_key_to_pem()
                .unwrap(),
            expires_at: Some("1893456000".to_string()),
            permissions: Vec::new(),
            enabled: true,
            key_version: Some(1),
        })
        .await;
    assert_eq!(
        manager
            .get_user("alice")
            .await
            .unwrap()
            .unwrap()
            .expires_at
            .as_deref(),
        Some("1893456000")
    );
    provider.remove_user("alice").await;
    assert!(manager.get_user("alice").await.unwrap().is_none());
}

#[test]
fn verified_tcp_auth_nonce_is_one_shot_and_expires() {
    let manager = UserManager::new(Arc::new(TestAuthorizationProvider::default()));
    let nonce = [9_u8; 32];
    assert!(manager.claim_tcp_auth_nonce("alice", nonce, 100, 200));
    assert!(!manager.claim_tcp_auth_nonce("alice", nonce, 100, 200));
    assert!(manager.claim_tcp_auth_nonce("bob", nonce, 100, 200));
    assert!(manager.claim_tcp_auth_nonce("alice", nonce, 201, 300));
}

#[test]
fn one_user_cannot_exhaust_the_global_tcp_replay_cache() {
    let manager = UserManager::new(Arc::new(TestAuthorizationProvider::default()));
    for index in 0..MAX_TCP_AUTH_REPLAY_ENTRIES_PER_USER {
        let mut nonce = [0_u8; 32];
        nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
        assert!(manager.claim_tcp_auth_nonce("alice", nonce, 100, 200));
    }
    assert!(!manager.claim_tcp_auth_nonce("alice", [0xff; 32], 100, 200));
    assert!(manager.claim_tcp_auth_nonce("bob", [0xff; 32], 100, 200));
}
