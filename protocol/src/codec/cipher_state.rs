use crate::compression::CompressionMode;
use crate::tcp_transport::TcpSessionCipher;
use crate::{ProtocolError, Result};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

/// TCP v2 会话加密与压缩模式的共享状态。
#[derive(Debug, Default)]
pub struct CipherState {
    session_cipher: OnceLock<Arc<TcpSessionCipher>>,
    /// 压缩模式：0=None，1=Zstd，2=Lz4，3=Gzip
    compression: AtomicU8,
}

impl CipherState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_compression(compression_mode: CompressionMode) -> Self {
        Self {
            session_cipher: OnceLock::new(),
            compression: AtomicU8::new(compression_mode.to_flag()),
        }
    }

    pub fn set_session_cipher(&self, cipher: Arc<TcpSessionCipher>) -> Result<()> {
        self.session_cipher.set(cipher).map_err(|_| {
            ProtocolError::InvalidMessage("TCP session cipher is already initialized".to_string())
        })
    }

    pub(crate) fn session_cipher(&self) -> Option<&Arc<TcpSessionCipher>> {
        self.session_cipher.get()
    }

    pub fn set_compression(&self, mode: CompressionMode) {
        self.compression.store(mode.to_flag(), Ordering::Release);
    }

    pub fn compression_mode(&self) -> CompressionMode {
        CompressionMode::from_flag(self.compression.load(Ordering::Acquire))
    }
}
