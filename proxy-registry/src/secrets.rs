use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const ENVELOPE_VERSION: u8 = 1;
const NONCE_BYTES: usize = 12;
const MIN_MASTER_SECRET_BYTES: usize = 32;
// These values are persisted as authenticated encryption metadata. Keep the original domain
// separator so existing databases remain decryptable after the service rename.
const KEY_VERIFIER_USERNAME: &str = "ppaass-proxy-web-key-verifier";
const KEY_VERIFIER_VERSION: i64 = 1;
const KEY_VERIFIER_PLAINTEXT: &str = "ppaass-proxy-web-key-verifier-v1";

#[derive(Clone)]
pub struct PrivateKeyCipher {
    key: [u8; 32],
}

#[derive(Debug, Error)]
pub enum PrivateKeyCipherError {
    #[error("私钥加密主密钥至少需要 {MIN_MASTER_SECRET_BYTES} 个 UTF-8 字节")]
    MasterSecretTooShort,

    #[error("加密私钥数据格式无效")]
    InvalidEnvelope,

    #[error("加密或解密私钥失败")]
    CryptographicFailure,

    #[error("解密出的私钥不是有效 UTF-8")]
    InvalidPlaintext,

    #[error("私钥加密主密钥校验值格式无效")]
    InvalidVerifier,

    #[error("私钥加密主密钥与数据库不匹配")]
    VerifierMismatch,
}

impl PrivateKeyCipher {
    pub fn new(master_secret: &str) -> Result<Self, PrivateKeyCipherError> {
        if master_secret.len() < MIN_MASTER_SECRET_BYTES {
            return Err(PrivateKeyCipherError::MasterSecretTooShort);
        }

        // 将可轮换的部署密钥规范化为 AES-256 key；原始密钥不会保存在结构体中。
        let key = Sha256::digest(master_secret.as_bytes()).into();
        Ok(Self { key })
    }

    /// 创建可存入数据库的认证校验信封，用于在启动时检测部署主密钥是否被替换。
    pub fn create_verifier(&self) -> Result<String, PrivateKeyCipherError> {
        self.encrypt(
            KEY_VERIFIER_USERNAME,
            KEY_VERIFIER_VERSION,
            KEY_VERIFIER_PLAINTEXT,
        )
        .map(|envelope| URL_SAFE_NO_PAD.encode(envelope))
    }

    /// 验证数据库中的认证信封是否由当前部署主密钥创建。
    pub fn verify_verifier(&self, verifier: &str) -> Result<(), PrivateKeyCipherError> {
        let envelope = URL_SAFE_NO_PAD
            .decode(verifier)
            .map_err(|_| PrivateKeyCipherError::InvalidVerifier)?;
        let plaintext = self
            .decrypt(KEY_VERIFIER_USERNAME, KEY_VERIFIER_VERSION, &envelope)
            .map_err(|_| PrivateKeyCipherError::VerifierMismatch)?;
        if plaintext.as_str() != KEY_VERIFIER_PLAINTEXT {
            return Err(PrivateKeyCipherError::VerifierMismatch);
        }
        Ok(())
    }

    pub fn encrypt(
        &self,
        username: &str,
        key_version: i64,
        private_key_pem: &str,
    ) -> Result<Vec<u8>, PrivateKeyCipherError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| PrivateKeyCipherError::CryptographicFailure)?;
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        rand::rng().fill(&mut nonce_bytes);
        let aad = associated_data(username, key_version);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: private_key_pem.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| PrivateKeyCipherError::CryptographicFailure)?;

        let mut envelope = Vec::with_capacity(1 + NONCE_BYTES + ciphertext.len());
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    pub fn decrypt(
        &self,
        username: &str,
        key_version: i64,
        envelope: &[u8],
    ) -> Result<Zeroizing<String>, PrivateKeyCipherError> {
        if envelope.len() <= 1 + NONCE_BYTES || envelope[0] != ENVELOPE_VERSION {
            return Err(PrivateKeyCipherError::InvalidEnvelope);
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| PrivateKeyCipherError::CryptographicFailure)?;
        let (nonce_bytes, ciphertext) = envelope[1..].split_at(NONCE_BYTES);
        let aad = associated_data(username, key_version);
        let mut plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(nonce_bytes),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| PrivateKeyCipherError::CryptographicFailure)?,
        );
        match String::from_utf8(std::mem::take(&mut *plaintext)) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(error) => {
                let _invalid_plaintext = Zeroizing::new(error.into_bytes());
                Err(PrivateKeyCipherError::InvalidPlaintext)
            }
        }
    }
}

fn associated_data(username: &str, key_version: i64) -> Vec<u8> {
    format!("ppaass-proxy-private-key\0{username}\0{key_version}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER_SECRET: &str = "test-only-master-secret-with-at-least-32-bytes";

    #[test]
    fn encrypts_and_authenticates_private_keys() {
        let cipher = PrivateKeyCipher::new(MASTER_SECRET).unwrap();
        let encrypted = cipher.encrypt("alice", 1, "private-pem").unwrap();
        assert!(
            !encrypted
                .windows("private-pem".len())
                .any(|value| value == b"private-pem")
        );
        assert_eq!(
            cipher.decrypt("alice", 1, &encrypted).unwrap().as_str(),
            "private-pem"
        );
        assert!(cipher.decrypt("bob", 1, &encrypted).is_err());
        assert!(cipher.decrypt("alice", 2, &encrypted).is_err());
    }

    #[test]
    fn rejects_short_master_secret() {
        assert!(matches!(
            PrivateKeyCipher::new("short"),
            Err(PrivateKeyCipherError::MasterSecretTooShort)
        ));
    }

    #[test]
    fn verifier_is_an_authenticated_envelope_and_rejects_a_different_key() {
        let cipher = PrivateKeyCipher::new(MASTER_SECRET).unwrap();
        let verifier = cipher.create_verifier().unwrap();
        let envelope = URL_SAFE_NO_PAD.decode(&verifier).unwrap();
        assert!(envelope.len() > 32);
        assert_eq!(envelope[0], ENVELOPE_VERSION);
        cipher.verify_verifier(&verifier).unwrap();

        let other = PrivateKeyCipher::new("another-test-only-master-secret-with-at-least-32-bytes")
            .unwrap();
        assert!(matches!(
            other.verify_verifier(&verifier),
            Err(PrivateKeyCipherError::VerifierMismatch)
        ));
        assert!(matches!(
            cipher.verify_verifier("not base64!"),
            Err(PrivateKeyCipherError::InvalidVerifier)
        ));
    }
}
