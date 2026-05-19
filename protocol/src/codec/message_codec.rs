use super::CipherState;
use crate::compression::{CompressionMode, compress, decompress};
use crate::message::{MAX_MESSAGE_SIZE, Message, MessageType};
use bytes::{Bytes, BytesMut};
use std::io;
use std::sync::Arc;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};
use tracing::error;

/// 启用压缩的最小负载大小（避免小消息产生额外开销）
const MIN_COMPRESSION_SIZE: usize = 64;

/// 使用长度分隔帧的代理协议消息编解码器。
/// 封装 tokio-util 的 LengthDelimitedCodec 以实现可靠的消息分帧。
/// 负责加密、解密、压缩与解压。
pub struct MessageCodec {
    inner: LengthDelimitedCodec,
    state: Arc<CipherState>,
}

impl MessageCodec {
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

    fn needs_crypto(_message_type: MessageType) -> bool {
        true
    }

    fn io_error(context: &str, err: impl std::fmt::Display) -> io::Error {
        error!("{}: {}", context, err);
        io::Error::new(io::ErrorKind::InvalidData, format!("{}: {}", context, err))
    }
}

impl Default for MessageCodec {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let frame = match self.inner.decode(src)? {
            Some(frame) => frame,
            None => return Ok(None),
        };

        let mut message: Message = bitcode::deserialize(&frame)
            .map_err(|e| Self::io_error("消息反序列化失败", e))?;

        if let Some(cipher) = self.state.cipher.get()
            && Self::needs_crypto(message.message_type)
        {
            let decrypted = cipher
                .decrypt(&message.payload)
                .map_err(|e| Self::io_error("解密失败", e))?;
            message.payload = decrypted;
        }

        let compression_mode = CompressionMode::from_flag(message.compression);
        if compression_mode != CompressionMode::None {
            let decompressed = decompress(&message.payload, compression_mode)
                .map_err(|e| Self::io_error("解压失败", e))?;
            message.payload = decompressed;
        }

        Ok(Some(message))
    }
}

impl Encoder<Message> for MessageCodec {
    type Error = io::Error;

    fn encode(&mut self, mut item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let compression_mode = self.state.compression_mode();
        if compression_mode != CompressionMode::None && item.payload.len() >= MIN_COMPRESSION_SIZE {
            match compress(&item.payload, compression_mode) {
                Ok(compressed) => {
                    if compressed.len() < item.payload.len() {
                        item.payload = compressed;
                        item.compression = compression_mode.to_flag();
                    }
                }
                Err(e) => error!("压缩失败：{}", e),
            }
        }

        if let Some(cipher) = self.state.cipher.get()
            && Self::needs_crypto(item.message_type)
        {
            let encrypted = cipher
                .encrypt(&item.payload)
                .map_err(|e| Self::io_error("加密失败", e))?;
            item.payload = encrypted;
        }

        let data = bitcode::serialize(&item)
            .map_err(|e| Self::io_error("消息序列化失败", e))?;
        self.inner.encode(Bytes::from(data), dst)
    }
}
