use super::{AesGcmCipher, RsaKeyPair};
use crate::error::{ProtocolError, Result};

pub struct CryptoManager {
    rsa_keypair: Option<RsaKeyPair>,
    aes_cipher: Option<AesGcmCipher>,
}

impl CryptoManager {
    pub fn new() -> Self {
        Self {
            rsa_keypair: None,
            aes_cipher: None,
        }
    }

    pub fn with_rsa_keypair(mut self, keypair: RsaKeyPair) -> Self {
        self.rsa_keypair = Some(keypair);
        self
    }

    pub fn with_aes_cipher(mut self, cipher: AesGcmCipher) -> Self {
        self.aes_cipher = Some(cipher);
        self
    }

    pub fn set_aes_cipher(&mut self, cipher: AesGcmCipher) {
        self.aes_cipher = Some(cipher);
    }

    pub fn rsa_encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.rsa_keypair
            .as_ref()
            .ok_or_else(|| ProtocolError::InvalidKey("RSA keypair not set".to_string()))?
            .encrypt(data)
    }

    pub fn rsa_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.rsa_keypair
            .as_ref()
            .ok_or_else(|| ProtocolError::InvalidKey("RSA keypair not set".to_string()))?
            .decrypt(data)
    }

    pub fn aes_encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.aes_cipher
            .as_ref()
            .ok_or_else(|| ProtocolError::InvalidKey("AES cipher not set".to_string()))?
            .encrypt(data)
    }

    pub fn aes_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.aes_cipher
            .as_ref()
            .ok_or_else(|| ProtocolError::InvalidKey("AES cipher not set".to_string()))?
            .decrypt(data)
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}
