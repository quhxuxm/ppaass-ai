use crate::config::{PERMISSION_PROXY_CONNECT_UDP, ProxyConfig, UserConfig};
use crate::error::{ProxyError, Result};
use crate::user_manager::UserManager;
use protocol::crypto::{RsaKeyPair, encrypt_oaep_sha256_labelled, verify_pss_sha256};
use protocol::udp_transport::{
    UDP_OAEP_LABEL, UDP_TRANSPORT_VERSION, UdpAuthInit, UdpAuthOk, UdpSessionCodec, UdpSessionId,
    UdpSessionRole, UdpSessionSecret, encode_auth_ok, encode_session_secret,
    udp_auth_ok_signature_transcript, udp_auth_proof_digest,
};
use rand::Rng;

pub(super) struct PreparedSession {
    pub(super) codec: UdpSessionCodec,
    pub(super) auth_ok_datagram: Vec<u8>,
    pub(super) authenticated_public_key_pem: String,
    pub(super) authenticated_key_version: Option<i64>,
    pub(super) expires_at: Option<i64>,
}

pub(super) async fn prepare_session(
    config: &ProxyConfig,
    user_manager: &UserManager,
    transport_identity: &RsaKeyPair,
    session_id: UdpSessionId,
    auth: &UdpAuthInit,
) -> Result<PreparedSession> {
    let user = user_manager
        .get_user(&auth.username)
        .await?
        .ok_or_else(|| ProxyError::UserNotFound(auth.username.clone()))?;
    let expires_at = validate_udp_auth(config, &user, auth)?;

    let user_public_key = RsaKeyPair::from_public_key_pem(&user.public_key_pem)
        .map_err(|error| ProxyError::Authentication(format!("Invalid public key: {error}")))?;
    let expected_proof = udp_auth_proof_digest(
        &session_id,
        &auth.username,
        auth.timestamp,
        &auth.client_nonce,
    );
    verify_pss_sha256(&user_public_key, &expected_proof, &auth.proof)
        .map_err(|error| ProxyError::Authentication(format!("Invalid UDP auth proof: {error}")))?;

    let mut master_key = [0_u8; 32];
    let mut server_nonce = [0_u8; 32];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut master_key);
    rng.fill_bytes(&mut server_nonce);
    let secret = UdpSessionSecret {
        version: UDP_TRANSPORT_VERSION,
        session_id,
        client_nonce: auth.client_nonce,
        master_key,
        server_nonce,
    };
    let encoded_secret = encode_session_secret(&secret)
        .map_err(|error| ProxyError::Authentication(error.to_string()))?;
    let encrypted_session_secret = encrypt_oaep_sha256_labelled(
        &user_public_key,
        UDP_OAEP_LABEL,
        &encoded_secret,
    )
    .map_err(|_| {
        ProxyError::Authentication("Failed to encrypt UDP authentication response".to_string())
    })?;
    let proxy_signature_transcript =
        udp_auth_ok_signature_transcript(&session_id, &expected_proof, &encrypted_session_secret)
            .map_err(|_| {
            ProxyError::Authentication(
                "Failed to build UDP Proxy identity signature context".to_string(),
            )
        })?;
    let proxy_signature = transport_identity
        .sign_pss_sha256(&proxy_signature_transcript)
        .map_err(|_| {
            ProxyError::Authentication("Failed to sign UDP authentication response".to_string())
        })?;
    let auth_ok_datagram = encode_auth_ok(
        session_id,
        &UdpAuthOk {
            encrypted_session_secret,
            proxy_signature,
        },
    )
    .map_err(|error| ProxyError::Authentication(error.to_string()))?;
    let codec = UdpSessionCodec::new(
        UdpSessionRole::Proxy,
        session_id,
        master_key,
        auth.client_nonce,
        server_nonce,
    )
    .map_err(|error| ProxyError::Authentication(error.to_string()))?;

    // RSA 验签、加密和编码可能跨过临近的绝对截止点；发送 AuthOk 前再用同一
    // 用户快照检查一次，避免为已经过期的身份建立新会话。
    validate_active_udp_user(&user, common::current_timestamp())?;

    Ok(PreparedSession {
        codec,
        auth_ok_datagram,
        authenticated_public_key_pem: user.public_key_pem,
        authenticated_key_version: user.key_version,
        expires_at,
    })
}

fn validate_udp_auth(
    config: &ProxyConfig,
    user: &UserConfig,
    auth: &UdpAuthInit,
) -> Result<Option<i64>> {
    if auth.username != user.username {
        return Err(ProxyError::Authentication("Username mismatch".to_string()));
    }
    let now = common::current_timestamp();
    let tolerance = config.replay_attack_tolerance.max(0) as u64;
    if now.abs_diff(auth.timestamp) > tolerance {
        return Err(ProxyError::Authentication("Timestamp expired".to_string()));
    }
    validate_active_udp_user(user, now)?;
    user.expires_at_unix_timestamp()
}

pub(super) async fn validate_session_authorization(
    user_manager: &UserManager,
    username: &str,
    authenticated_public_key_pem: &str,
    authenticated_key_version: Option<i64>,
) -> Result<()> {
    let user = user_manager
        .get_user(username)
        .await?
        .ok_or_else(|| ProxyError::Authentication("User no longer exists".to_string()))?;
    if user.username != username {
        return Err(ProxyError::Authentication("Username mismatch".to_string()));
    }
    if user.public_key_pem != authenticated_public_key_pem {
        return Err(ProxyError::Authentication(
            "User key was rotated".to_string(),
        ));
    }
    if let Some(authenticated_key_version) = authenticated_key_version
        && user.key_version != Some(authenticated_key_version)
    {
        return Err(ProxyError::Authentication(
            "User key version changed".to_string(),
        ));
    }
    validate_active_udp_user(&user, common::current_timestamp())
}

fn validate_active_udp_user(user: &UserConfig, now: i64) -> Result<()> {
    if !user.enabled {
        return Err(ProxyError::Authentication("User disabled".to_string()));
    }
    if !user.has_permission(PERMISSION_PROXY_CONNECT_UDP) {
        return Err(ProxyError::Authentication(format!(
            "Permission denied: {PERMISSION_PROXY_CONNECT_UDP}"
        )));
    }
    if user.is_expired_at(now)? {
        return Err(ProxyError::Authentication("User expired".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_session_authorization;
    use crate::user_manager::UserManager;
    use protocol::RsaKeyPair;
    use proxy_user_store::{
        AccountActor, AccountRepository, NewAdminAccount, SqliteUserRepository, UserRepository,
        UserUpdate,
    };
    use std::sync::Arc;
    use tempfile::TempDir;

    #[tokio::test]
    async fn live_session_revalidation_detects_disable_permission_revocation_and_key_rotation() {
        let directory = TempDir::new().unwrap();
        let database_path = directory.path().join("users.sqlite3");
        let store = Arc::new(SqliteUserRepository::connect(&database_path).await.unwrap());
        create_test_admin(&store).await;
        let manager = UserManager::new(store.clone() as Arc<dyn UserRepository>);
        let first_public_key = RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap()
            .trim()
            .to_string();
        let created = store
            .create_user("alice", &first_public_key, Some(i64::MAX))
            .await
            .unwrap();

        validate_session_authorization(
            &manager,
            "alice",
            &first_public_key,
            Some(created.key_version),
        )
        .await
        .unwrap();

        store
            .update_user(
                "alice",
                UserUpdate {
                    enabled: Some(false),
                    changed_by: Some(test_actor()),
                    audit_reason: Some("测试停用 UDP 用户".to_string()),
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();
        assert!(
            validate_session_authorization(
                &manager,
                "alice",
                &first_public_key,
                Some(created.key_version),
            )
            .await
            .is_err()
        );

        store
            .update_user(
                "alice",
                UserUpdate {
                    enabled: Some(true),
                    permissions: Some(vec!["proxy.connect.tcp".to_string()]),
                    changed_by: Some(test_actor()),
                    audit_reason: Some("测试撤销 UDP 权限".to_string()),
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();
        assert!(
            validate_session_authorization(
                &manager,
                "alice",
                &first_public_key,
                Some(created.key_version),
            )
            .await
            .is_err()
        );

        store
            .update_user(
                "alice",
                UserUpdate {
                    permissions: Some(vec!["proxy.connect.udp".to_string()]),
                    expires_at: Some(Some(common::current_timestamp())),
                    changed_by: Some(test_actor()),
                    audit_reason: Some("测试恢复 UDP 权限并设置过期时间".to_string()),
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();
        assert!(
            validate_session_authorization(
                &manager,
                "alice",
                &first_public_key,
                Some(created.key_version),
            )
            .await
            .is_err()
        );

        let second_public_key = RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap()
            .trim()
            .to_string();
        store
            .update_user(
                "alice",
                UserUpdate {
                    public_key_pem: Some(second_public_key),
                    permissions: Some(vec!["proxy.connect.udp".to_string()]),
                    expires_at: Some(Some(i64::MAX)),
                    changed_by: Some(test_actor()),
                    audit_reason: Some("测试轮换 UDP 用户密钥".to_string()),
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();
        assert!(
            validate_session_authorization(
                &manager,
                "alice",
                &first_public_key,
                Some(created.key_version),
            )
            .await
            .is_err()
        );

        // 即使管理员把公钥内容恢复为握手时的 PEM，单调递增的 key_version
        // 也必须永久淘汰旧会话，避免公钥内容比较的 ABA。
        store
            .update_user(
                "alice",
                UserUpdate {
                    public_key_pem: Some(first_public_key.clone()),
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();
        assert!(
            validate_session_authorization(
                &manager,
                "alice",
                &first_public_key,
                Some(created.key_version),
            )
            .await
            .is_err()
        );
    }

    fn test_actor() -> AccountActor {
        AccountActor {
            account_id: "test-admin".to_string(),
            login_name: "test-admin".to_string(),
        }
    }

    async fn create_test_admin(store: &SqliteUserRepository) {
        store
            .bootstrap_admin_if_absent(NewAdminAccount {
                account_id: "test-admin".to_string(),
                login_name: "test-admin".to_string(),
                password_hash: None,
                display_name: None,
                email: None,
                avatar_url: None,
            })
            .await
            .unwrap();
    }
}
