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
struct TestClientConfig {
    username: String,
    private_key_pem: String,
}

impl ClientConnectionConfig for TestClientConfig {
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
async fn authenticated_speed_test_returns_exact_requested_bytes() {
    let result = run_speed_test(true).await.unwrap();
    assert_eq!(result, u64::from(MIN_SPEED_TEST_DOWNLOAD_BYTES));
}

#[tokio::test]
async fn speed_test_requires_tcp_connect_permission() {
    let error = run_speed_test(false).await.unwrap_err();
    assert!(error.to_string().contains("Authorization"));
}

async fn run_speed_test(allowed: bool) -> std::io::Result<u64> {
    let key = RsaKeyPair::generate(2048).unwrap();
    let username = "speed-user".to_string();
    let permissions = if allowed {
        vec![PERMISSION_PROXY_CONNECT_TCP.to_string()]
    } else {
        vec![]
    };
    let user = UserConfig {
        username: username.clone(),
        public_key_pem: key.public_key_to_pem().unwrap(),
        expires_at: Some(i64::MAX.to_string()),
        permissions,
        enabled: true,
        key_version: Some(1),
    };
    let provider = Arc::new(TestAuthorizationProvider::new([user]));
    let users = Arc::new(UserManager::new(provider));
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
        let authenticated_username = server.peek_auth_username().await.unwrap();
        let user = users
            .get_user(&authenticated_username)
            .await
            .unwrap()
            .unwrap();
        server
            .authenticate(proxy_config.as_ref(), user)
            .await
            .unwrap();
        server
            .handle_connect_request(&authenticated_username)
            .await
            .unwrap();
    };
    let client_config = TestClientConfig {
        username,
        private_key_pem: key.private_key_to_pem().unwrap(),
    };
    let client_task = async move {
        AuthenticatedConnection::authenticate_stream(client_io, &client_config)
            .await?
            .download_speed_test(MIN_SPEED_TEST_DOWNLOAD_BYTES)
            .await
    };
    let (_, result) = tokio::join!(server_task, client_task);
    result
}
