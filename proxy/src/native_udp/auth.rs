use crate::config::{ProxyConfig, UserConfig};
use crate::error::{ProxyError, Result};
use crate::user_manager::UserManager;
use protocol::crypto::{RsaKeyPair, encrypt_oaep_sha256, verify_pss_sha256};
use protocol::udp_transport::{
    UdpAuthInit, UdpAuthOk, UdpSessionCodec, UdpSessionId, UdpSessionRole, UdpSessionSecret,
    encode_auth_ok, encode_session_secret, udp_auth_proof_digest,
};
use rand::Rng;

pub(super) struct PreparedSession {
    pub(super) codec: UdpSessionCodec,
    pub(super) auth_ok_datagram: Vec<u8>,
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
    validate_udp_auth(config, &user, auth)?;

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
        session_id,
        client_nonce: auth.client_nonce,
        master_key,
        server_nonce,
    };
    let encoded_secret = encode_session_secret(&secret)
        .map_err(|error| ProxyError::Authentication(error.to_string()))?;
    let encrypted_session_secret = encrypt_oaep_sha256(&user_public_key, &encoded_secret)
        .map_err(|error| ProxyError::Authentication(error.to_string()))?;
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

    Ok(PreparedSession {
        codec,
        auth_ok_datagram,
    })
}

fn validate_udp_auth(config: &ProxyConfig, user: &UserConfig, auth: &UdpAuthInit) -> Result<()> {
    if auth.username != user.username {
        return Err(ProxyError::Authentication("Username mismatch".to_string()));
    }
    let now = common::current_timestamp();
    let tolerance = config.replay_attack_tolerance.max(0) as u64;
    if now.abs_diff(auth.timestamp) > tolerance {
        return Err(ProxyError::Authentication("Timestamp expired".to_string()));
    }
    if user.is_expired_at(now)? {
        return Err(ProxyError::Authentication("User expired".to_string()));
    }
    Ok(())
}
