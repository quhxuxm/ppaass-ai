use crate::config::{PERMISSION_PROXY_CONNECT_UDP, ProxyConfig, UserConfig};
use crate::error::{ProxyError, Result};
use crate::user_manager::UserManager;
use protocol::crypto::{
    encrypt_oaep_sha256_labelled, parse_public_key_pem_cached, verify_pss_sha256,
};
use protocol::udp_transport::{
    UDP_OAEP_LABEL, UDP_TRANSPORT_VERSION, UdpAuthInit, UdpAuthOk, UdpSessionCodec, UdpSessionId,
    UdpSessionRole, UdpSessionSecret, encode_auth_ok, encode_session_secret, udp_auth_proof_digest,
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
    session_id: UdpSessionId,
    auth: &UdpAuthInit,
) -> Result<PreparedSession> {
    let user = user_manager
        .get_user(&auth.username)
        .await?
        .ok_or_else(|| ProxyError::UserNotFound(auth.username.clone()))?;
    let expires_at = validate_udp_auth(config, &user, auth)?;

    let user_public_key = parse_public_key_pem_cached(&user.public_key_pem)
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
    let auth_ok_datagram = encode_auth_ok(
        session_id,
        &UdpAuthOk {
            encrypted_session_secret,
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

pub async fn validate_session_authorization(
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
