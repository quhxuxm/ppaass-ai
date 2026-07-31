mod support;

use protocol::RsaKeyPair;
use proxy_entry::config::{PERMISSION_PROXY_CONNECT_TCP, UserConfig};
use proxy_entry::connection::ConnectionAuthorization;
use proxy_entry::user_manager::UserManager;
use std::sync::Arc;
use std::time::Duration;
use support::TestAuthorizationProvider;

fn test_user(
    public_key_pem: &str,
    enabled: bool,
    key_version: i64,
    expires_at: Option<i64>,
) -> UserConfig {
    UserConfig {
        username: "alice".to_string(),
        public_key_pem: public_key_pem.to_string(),
        expires_at: expires_at.map(|value| value.to_string()),
        permissions: vec![PERMISSION_PROXY_CONNECT_TCP.to_string()],
        enabled,
        key_version: Some(key_version),
    }
}

#[tokio::test]
async fn absolute_expiry_closes_idle_connection() {
    let expires_at = common::current_timestamp() + 30;
    let public_key = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    let provider = Arc::new(TestAuthorizationProvider::new([test_user(
        &public_key,
        true,
        1,
        Some(expires_at),
    )]));
    let manager = Arc::new(UserManager::new(provider));
    let user = manager.get_user("alice").await.unwrap().unwrap();
    let authorization = ConnectionAuthorization::new(manager, &user).unwrap();

    tokio::time::pause();
    let guard =
        tokio::spawn(async move { authorization.enforce(PERMISSION_PROXY_CONNECT_TCP, 5).await });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(20)).await;
    assert!(!guard.is_finished());

    tokio::time::advance(Duration::from_secs(15)).await;
    assert!(guard.await.unwrap().is_err());
}

#[tokio::test]
async fn key_version_rejects_public_key_aba() {
    let public_key_a = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    let public_key_b = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    let provider = Arc::new(TestAuthorizationProvider::new([test_user(
        &public_key_a,
        true,
        1,
        Some(i64::MAX),
    )]));
    let manager = Arc::new(UserManager::new(provider.clone()));
    let user = manager.get_user("alice").await.unwrap().unwrap();
    let authorization = ConnectionAuthorization::new(manager, &user).unwrap();

    provider
        .set_user(test_user(&public_key_b, true, 2, Some(i64::MAX)))
        .await;
    provider
        .set_user(test_user(&public_key_a, true, 3, Some(i64::MAX)))
        .await;

    assert!(
        authorization
            .validate(PERMISSION_PROXY_CONNECT_TCP)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn periodic_recheck_closes_disabled_connection_within_five_seconds() {
    let public_key = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    let provider = Arc::new(TestAuthorizationProvider::new([test_user(
        &public_key,
        true,
        1,
        Some(i64::MAX),
    )]));
    let manager = Arc::new(UserManager::new(provider.clone()));
    let user = manager.get_user("alice").await.unwrap().unwrap();
    let authorization = ConnectionAuthorization::new(manager, &user).unwrap();

    provider
        .set_user(test_user(&public_key, false, 1, Some(i64::MAX)))
        .await;
    tokio::time::pause();
    let guard =
        tokio::spawn(async move { authorization.enforce(PERMISSION_PROXY_CONNECT_TCP, 5).await });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(4)).await;
    assert!(!guard.is_finished());

    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(guard.await.unwrap().is_err());
}
