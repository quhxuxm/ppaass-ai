mod support;

use common::{AuthenticatedConnection, ClientConnectionConfig};
use protocol::{CompressionMode, MIN_SPEED_TEST_DOWNLOAD_BYTES, RsaKeyPair};
use proxy_entry::access_log::AccessRecorder;
use proxy_entry::config::{PERMISSION_PROXY_CONNECT_TCP, UserConfig};
use proxy_entry::connection::{EgressState, ServerConnection};
use proxy_entry::user_manager::UserManager;
use std::sync::Arc;
use std::time::Duration;
use support::TestAuthorizationProvider;

#[derive(Debug)]
struct TestConfig {
    username: String,
    private_key_pem: String,
}

impl ClientConnectionConfig for TestConfig {
    fn remote_addr(&self) -> String {
        "unused.invalid:1".to_string()
    }
    fn username(&self) -> String {
        self.username.clone()
    }
    fn private_key_pem(&self) -> Result<String, String> {
        Ok(self.private_key_pem.clone())
    }
    fn timeout_duration(&self) -> Duration {
        Duration::from_secs(5)
    }
}

#[tokio::test]
async fn auth_connect_speed_test_returns_exact_requested_bytes() {
    let result = run_speed_test(true).await.unwrap();
    assert_eq!(result, u64::from(MIN_SPEED_TEST_DOWNLOAD_BYTES));
}

#[tokio::test]
async fn speed_test_requires_tcp_connect_permission() {
    let error = run_speed_test(false).await.unwrap_err();
    assert!(error.to_string().contains("Authorization"));
}

async fn run_speed_test(allowed: bool) -> std::io::Result<u64> {
    let identity = RsaKeyPair::generate(2048).unwrap();
    let username = "speed-user".to_string();
    let user = UserConfig {
        username: username.clone(),
        public_key_pem: identity.public_key_to_pem().unwrap(),
        expires_at: Some(i64::MAX.to_string()),
        permissions: allowed
            .then(|| vec![PERMISSION_PROXY_CONNECT_TCP.to_string()])
            .unwrap_or_default(),
        enabled: true,
        key_version: Some(1),
    };
    let users = Arc::new(UserManager::new(Arc::new(TestAuthorizationProvider::new(
        [user],
    ))));
    let proxy_config = Arc::new(support::proxy_config("auth_timeout_secs = 5"));
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let mut server = ServerConnection::new(
        server_io,
        CompressionMode::None,
        proxy_config.clone(),
        users.clone(),
        Arc::new(EgressState::new(None, None).unwrap()),
        AccessRecorder::default(),
    );
    let server_task = async move {
        let name = server.peek_auth_username().await.unwrap();
        let user = users.get_user(&name).await.unwrap().unwrap();
        server
            .authenticate(proxy_config.as_ref(), user)
            .await
            .unwrap();
        server.handle_authenticated_intent().await.unwrap();
    };
    let client = TestConfig {
        username,
        private_key_pem: identity.private_key_to_pem().unwrap(),
    };
    let client_task = async move {
        AuthenticatedConnection::establish_speed_test(
            client_io,
            &client,
            MIN_SPEED_TEST_DOWNLOAD_BYTES,
        )
        .await?
        .download_speed_test(u64::from(MIN_SPEED_TEST_DOWNLOAD_BYTES))
        .await
    };
    let (_, result) = tokio::join!(server_task, client_task);
    result
}
