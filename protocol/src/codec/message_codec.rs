use super::CipherState;
use crate::compression::{CompressionMode, compress, decompress};
use crate::message::{MAX_MESSAGE_SIZE, Message, MessageType, PROTOCOL_VERSION};
use bytes::{Bytes, BytesMut};
use std::io;
use std::sync::Arc;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};
use tracing::error;

/// 启用压缩的最小负载大小（避免小消息产生额外开销）
const MIN_COMPRESSION_SIZE: usize = 64;
/// Authentication runs before record protection is installed, so its
/// cleartext envelope is intentionally much smaller than a data frame.
const MAX_UNPROTECTED_AUTH_PAYLOAD_SIZE: usize = 4 * 1024;
const MAX_UNPROTECTED_AUTH_FRAME_SIZE: usize = 8 * 1024;

/// 使用长度分隔帧的代理协议消息编解码器。
/// 封装 tokio-util 的 LengthDelimitedCodec 以实现可靠的消息分帧。
/// 负责加密、解密、压缩与解压。
pub struct MessageCodec {
    inner: LengthDelimitedCodec,
    state: Arc<CipherState>,
}

impl MessageCodec {
    pub fn new(state: Arc<CipherState>) -> Self {
        let inner = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_MESSAGE_SIZE)
            .length_field_type::<u32>()
            .big_endian()
            .new_codec();
        Self { inner, state }
    }

    fn is_auth(message_type: MessageType) -> bool {
        matches!(
            message_type,
            MessageType::AuthRequest | MessageType::AuthResponse
        )
    }

    fn io_error(context: &str, err: impl std::fmt::Display) -> io::Error {
        error!("{}: {}", context, err);
        io::Error::new(io::ErrorKind::InvalidData, format!("{}: {}", context, err))
    }

    fn validate_wire_metadata(message: &Message) -> io::Result<()> {
        if message.version != PROTOCOL_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported TCP protocol version",
            ));
        }
        if message.compression > CompressionMode::Gzip.to_flag() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TCP frame compression mode",
            ));
        }
        Ok(())
    }
}

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // LengthDelimitedCodec otherwise trusts its global 4 MiB limit and
        // waits for that entire allocation before returning a frame. During
        // authentication we can reject an oversized declared length as soon as
        // the four-byte prefix arrives.
        if self.state.session_cipher().is_none() && src.len() >= 4 {
            let declared_len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
            if declared_len > MAX_UNPROTECTED_AUTH_FRAME_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "declared unprotected authentication frame is too large",
                ));
            }
        }
        let frame = match self.inner.decode(src)? {
            Some(frame) => frame,
            None => return Ok(None),
        };
        if self.state.session_cipher().is_none() && frame.len() > MAX_UNPROTECTED_AUTH_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unprotected authentication wire frame is too large",
            ));
        }

        let mut message: Message =
            bitcode::deserialize(&frame).map_err(|e| Self::io_error("消息反序列化失败", e))?;
        Self::validate_wire_metadata(&message)?;

        if let Some(cipher) = self.state.session_cipher() {
            if Self::is_auth(message.message_type) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authentication frames are forbidden after session establishment",
                ));
            }
            message.payload = cipher
                .open(
                    message.message_type,
                    message.compression,
                    message.sequence,
                    &message.payload,
                )
                .map_err(|e| Self::io_error("TCP 帧认证失败", e))?;
        } else {
            if !Self::is_auth(message.message_type) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "record-protected TCP frame required after authentication",
                ));
            }
            if message.sequence != 0 || message.compression != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid unprotected authentication frame metadata",
                ));
            }
            if message.payload.len() > MAX_UNPROTECTED_AUTH_PAYLOAD_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unprotected authentication frame is too large",
                ));
            }
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
        if item.version != PROTOCOL_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cannot encode an unsupported TCP protocol version",
            ));
        }
        item.sequence = 0;
        item.compression = 0;
        let compression_mode = self.state.compression_mode();
        if !Self::is_auth(item.message_type)
            && compression_mode != CompressionMode::None
            && item.payload.len() >= MIN_COMPRESSION_SIZE
        {
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

        if let Some(cipher) = self.state.session_cipher() {
            if Self::is_auth(item.message_type) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authentication frames are forbidden after session establishment",
                ));
            }
            let (sequence, ciphertext) = cipher
                .seal(item.message_type, item.compression, &item.payload)
                .map_err(|e| Self::io_error("TCP 帧加密失败", e))?;
            item.sequence = sequence;
            item.payload = ciphertext;
        } else {
            if !Self::is_auth(item.message_type) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "refusing to send an unprotected non-authentication frame",
                ));
            }
            if item.payload.len() > MAX_UNPROTECTED_AUTH_PAYLOAD_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unprotected authentication frame is too large",
                ));
            }
        }

        let data = bitcode::serialize(&item).map_err(|e| Self::io_error("消息序列化失败", e))?;
        self.inner.encode(Bytes::from(data), dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_preauth_length_prefix_is_rejected_immediately() {
        let state = Arc::new(CipherState::new());
        let mut codec = MessageCodec::new(state);
        let mut input =
            BytesMut::from(&(MAX_UNPROTECTED_AUTH_FRAME_SIZE as u32 + 1).to_be_bytes()[..]);

        assert!(codec.decode(&mut input).is_err());
        assert_eq!(input.len(), 4);
    }

    #[test]
    fn previous_tcp_protocol_envelope_has_no_fallback() {
        let legacy = Message {
            version: PROTOCOL_VERSION - 1,
            message_type: MessageType::AuthRequest,
            compression: 0,
            sequence: 0,
            payload: Vec::new(),
        };
        let encoded = bitcode::serialize(&legacy).unwrap();
        let mut input = BytesMut::new();
        input.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        input.extend_from_slice(&encoded);
        let mut codec = MessageCodec::new(Arc::new(CipherState::new()));

        assert!(codec.decode(&mut input).is_err());
    }
}
