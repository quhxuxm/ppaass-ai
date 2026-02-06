use super::CipherState;
use crate::compression::{CompressionMode, compress, decompress};
use crate::message::{MAX_MESSAGE_SIZE, Message, MessageType};
use bytes::{Bytes, BytesMut};
use std::io;
use std::sync::Arc;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

/// Minimum payload size to apply compression (avoid overhead for small messages)
const MIN_COMPRESSION_SIZE: usize = 64;

/// Codec for proxy protocol messages using length-delimited framing.
/// Uses tokio-util's LengthDelimitedCodec for reliable message framing.
/// Handles encryption, decryption, compression, and decompression transparently.
pub struct ProxyCodec {
    inner: LengthDelimitedCodec,
    state: Arc<CipherState>,
}

impl ProxyCodec {
    pub fn new(state: Option<Arc<CipherState>>) -> Self {
        let inner = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_MESSAGE_SIZE)
            .length_field_type::<u32>()
            .big_endian()
            .new_codec();
        Self {
            inner,
            state: state.unwrap_or_default(),
        }
    }
}

impl Default for ProxyCodec {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Decoder for ProxyCodec {
    type Item = Message;
    type Error = io::Error;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        // Use LengthDelimitedCodec to handle framing
        match self.inner.decode(src)? {
            Some(frame) => {
                // Deserialize the message from the frame
                let mut message: Message = bitcode::deserialize(&frame).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to deserialize message: {}", e),
                    )
                })?;

                // Decompress payload if compression flag is set
                let compression_mode = CompressionMode::from_flag(message.compression);
                if compression_mode != CompressionMode::None {
                    let decompressed =
                        decompress(&message.payload, compression_mode).map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("Decompression failed: {}", e),
                            )
                        })?;
                    message.payload = decompressed;
                }

                // Decrypt payload if cipher is present and message type requires encryption
                if let Some(cipher) = self.state.cipher.get()
                    && !matches!(
                        message.message_type,
                        MessageType::AuthRequest | MessageType::AuthResponse
                    )
                {
                    let decrypted = cipher.decrypt(&message.payload).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Decryption failed: {}", e),
                        )
                    })?;
                    message.payload = decrypted;
                }

                Ok(Some(message))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<Message> for ProxyCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        mut item: Message,
        dst: &mut BytesMut,
    ) -> std::result::Result<(), Self::Error> {
        // Encrypt payload if cipher is present and message type requires encryption
        if let Some(cipher) = self.state.cipher.get()
            && !matches!(
                item.message_type,
                MessageType::AuthRequest | MessageType::AuthResponse
            )
        {
            let encrypted = cipher.encrypt(&item.payload).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Encryption failed: {}", e),
                )
            })?;
            item.payload = encrypted;
        }

        // Compress payload if compression is enabled and payload is large enough
        let compression_mode = self.state.compression_mode();
        if compression_mode != CompressionMode::None && item.payload.len() >= MIN_COMPRESSION_SIZE {
            match compress(&item.payload, compression_mode) {
                Ok(compressed) => {
                    // Only use compressed data if it's actually smaller
                    if compressed.len() < item.payload.len() {
                        item.payload = compressed;
                        item.compression = compression_mode.to_flag();
                    }
                }
                Err(_) => {
                    // Fall back to uncompressed on error
                }
            }
        }

        // Serialize the message
        let data = bitcode::serialize(&item).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize message: {}", e),
            )
        })?;

        // Use LengthDelimitedCodec to handle framing
        self.inner.encode(Bytes::from(data), dst)
    }
}
