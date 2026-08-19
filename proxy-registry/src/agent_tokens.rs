use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const TOKEN_VERSION: u8 = 1;
const NONCE_BYTES: usize = 12;
const MIN_MASTER_SECRET_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 4 * 1024;
pub const AGENT_ACCESS_TOKEN_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const AGENT_PROFILE_REFRESH_SECONDS: u32 = 60;
const KEY_DERIVATION_DOMAIN: &[u8] = b"ppaass-agent-access-token-key-v1\0";
const TOKEN_AAD: &[u8] = b"ppaass-agent-access-token-v1";

#[derive(Clone)]
pub struct AgentAccessTokenService {
    key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAccessTokenClaims {
    pub account_id: String,
    pub expires_at: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct IssuedAgentAccessToken {
    pub token: String,
    pub expires_at: i64,
}

#[derive(Debug, Error)]
pub enum AgentAccessTokenError {
    #[error("Agent token 主密钥至少需要 {MIN_MASTER_SECRET_BYTES} 个 UTF-8 字节")]
    MasterSecretTooShort,

    #[error("Agent token 格式或认证信息无效")]
    InvalidToken,

    #[error("Agent token 已过期")]
    Expired,

    #[error("Agent token 加密失败")]
    CryptographicFailure,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenPayload {
    account_id: String,
    expires_at: i64,
}

impl AgentAccessTokenService {
    pub fn new(master_secret: &str) -> Result<Self, AgentAccessTokenError> {
        if master_secret.len() < MIN_MASTER_SECRET_BYTES {
            return Err(AgentAccessTokenError::MasterSecretTooShort);
        }
        let mut digest = Sha256::new();
        digest.update(KEY_DERIVATION_DOMAIN);
        digest.update(master_secret.as_bytes());
        Ok(Self {
            key: digest.finalize().into(),
        })
    }

    pub fn issue(&self, account_id: &str) -> Result<IssuedAgentAccessToken, AgentAccessTokenError> {
        self.issue_at(account_id, now())
    }

    pub fn verify(&self, token: &str) -> Result<AgentAccessTokenClaims, AgentAccessTokenError> {
        self.verify_at(token, now())
    }

    #[doc(hidden)]
    pub fn issue_at(
        &self,
        account_id: &str,
        issued_at: i64,
    ) -> Result<IssuedAgentAccessToken, AgentAccessTokenError> {
        if account_id.is_empty() {
            return Err(AgentAccessTokenError::InvalidToken);
        }
        let expires_at = issued_at
            .checked_add(AGENT_ACCESS_TOKEN_TTL_SECONDS)
            .ok_or(AgentAccessTokenError::InvalidToken)?;
        let plaintext = serde_json::to_vec(&TokenPayload {
            account_id: account_id.to_string(),
            expires_at,
        })
        .map_err(|_| AgentAccessTokenError::InvalidToken)?;
        let cipher = self.cipher()?;
        let mut nonce = [0_u8; NONCE_BYTES];
        rand::rng().fill(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: TOKEN_AAD,
                },
            )
            .map_err(|_| AgentAccessTokenError::CryptographicFailure)?;
        let mut envelope = Vec::with_capacity(1 + NONCE_BYTES + ciphertext.len());
        envelope.push(TOKEN_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(IssuedAgentAccessToken {
            token: URL_SAFE_NO_PAD.encode(envelope),
            expires_at,
        })
    }

    #[doc(hidden)]
    pub fn verify_at(
        &self,
        token: &str,
        timestamp: i64,
    ) -> Result<AgentAccessTokenClaims, AgentAccessTokenError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(AgentAccessTokenError::InvalidToken);
        }
        let envelope = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| AgentAccessTokenError::InvalidToken)?;
        if envelope.len() <= 1 + NONCE_BYTES || envelope[0] != TOKEN_VERSION {
            return Err(AgentAccessTokenError::InvalidToken);
        }
        let (nonce, ciphertext) = envelope[1..].split_at(NONCE_BYTES);
        let plaintext = self
            .cipher()?
            .decrypt(
                &nonce.try_into().unwrap(),
                Payload {
                    msg: ciphertext,
                    aad: TOKEN_AAD,
                },
            )
            .map_err(|_| AgentAccessTokenError::InvalidToken)?;
        let payload = serde_json::from_slice::<TokenPayload>(&plaintext)
            .map_err(|_| AgentAccessTokenError::InvalidToken)?;
        if payload.account_id.is_empty() {
            return Err(AgentAccessTokenError::InvalidToken);
        }
        if payload.expires_at <= timestamp {
            return Err(AgentAccessTokenError::Expired);
        }
        Ok(AgentAccessTokenClaims {
            account_id: payload.account_id,
            expires_at: payload.expires_at,
        })
    }

    fn cipher(&self) -> Result<Aes256Gcm, AgentAccessTokenError> {
        Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| AgentAccessTokenError::CryptographicFailure)
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
