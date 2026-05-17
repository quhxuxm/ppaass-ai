use crate::compression::CompressionMode;
use crate::crypto::AesGcmCipher;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

/// 加密密钥与压缩模式的共享状态
#[derive(Debug, Default)]
pub struct CipherState {
    pub cipher: OnceLock<Arc<AesGcmCipher>>,
    /// 压缩模式：0=None，1=Zstd，2=Lz4，3=Gzip
    compression: AtomicU8,
}

impl CipherState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_compression(compression_mode: CompressionMode) -> Self {
        Self {
            cipher: OnceLock::new(),
            compression: AtomicU8::new(compression_mode.to_flag()),
        }
    }

    pub fn set_cipher(&self, cipher: Arc<AesGcmCipher>) {
        let _ = self.cipher.set(cipher);
    }

    pub fn set_compression(&self, mode: CompressionMode) {
        self.compression.store(mode.to_flag(), Ordering::Release);
    }

    pub fn compression_mode(&self) -> CompressionMode {
        CompressionMode::from_flag(self.compression.load(Ordering::Acquire))
    }
}
