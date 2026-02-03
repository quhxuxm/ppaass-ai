use crate::crypto::AesGcmCipher;
use std::sync::{Arc, OnceLock};

/// Shared state for the cipher key
#[derive(Debug, Default)]
pub struct CipherState {
    pub cipher: OnceLock<Arc<AesGcmCipher>>,
}

impl CipherState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_cipher(&self, cipher: Arc<AesGcmCipher>) {
        let _ = self.cipher.set(cipher);
    }
}
