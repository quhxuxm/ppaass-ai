use super::values::{AES_KEY_SIZE, NONCE_SIZE};
use crate::error::{ProtocolError, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rsa::rand_core::{OsRng, RngCore};

pub struct AesGcmCipher {
    key: [u8; AES_KEY_SIZE],
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for AesGcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmCipher")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl AesGcmCipher {
    pub fn new() -> Self {
        let mut key = [0u8; AES_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        Self { key, cipher }
    }

    pub fn from_key(key: [u8; AES_KEY_SIZE]) -> Self {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        Self { key, cipher }
    }

    pub fn key(&self) -> &[u8; AES_KEY_SIZE] {
        &self.key
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let ciphertext = self
            .cipher
            .encrypt(&nonce, data)
            .map_err(|e| ProtocolError::Encryption(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE {
            return Err(ProtocolError::Decryption("Data too short".to_string()));
        }

        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let ciphertext = &data[NONCE_SIZE..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| ProtocolError::Decryption(e.to_string()))
    }
}

impl Default for AesGcmCipher {
    fn default() -> Self {
        Self::new()
    }
}
