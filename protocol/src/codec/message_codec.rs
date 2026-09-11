use super::CipherState;
use crate::compression::{CompressionMode, compress, decompress};
use crate::message::{MAX_MESSAGE_SIZE, Message, MessageType, PROTOCOL_VERSION};
use bytes::{BufMut, BytesMut};
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
const WIRE_HEADER_LEN: usize = 11;

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

    fn decode_wire_message(mut frame: BytesMut) -> io::Result<Message> {
        if frame.len() < WIRE_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TCP frame is shorter than its record header",
            ));
        }
        let message_type = match frame[1] {
            1 => MessageType::AuthRequest,
            2 => MessageType::AuthResponse,
            3 => MessageType::ConnectRequest,
            4 => MessageType::ConnectResponse,
            5 => MessageType::Data,
            6 => MessageType::Error,
            7 => MessageType::SpeedTestRequest,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid TCP frame message type",
                ));
            }
        };
        let mut sequence = [0_u8; 8];
        sequence.copy_from_slice(&frame[3..WIRE_HEADER_LEN]);
        let payload = frame.split_off(WIRE_HEADER_LEN).to_vec();
        Ok(Message {
            version: frame[0],
            message_type,
            compression: frame[2],
            sequence: u64::from_be_bytes(sequence),
            payload,
        })
    }

    fn encode_wire_message(item: Message, dst: &mut BytesMut) -> io::Result<()> {
        let frame_len = WIRE_HEADER_LEN
            .checked_add(item.payload.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TCP frame is too large"))?;
        if frame_len > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TCP frame is too large",
            ));
        }
        dst.reserve(4 + frame_len);
        dst.put_u32(frame_len as u32);
        dst.put_u8(item.version);
        dst.put_u8(item.message_type as u8);
        dst.put_u8(item.compression);
        dst.put_u64(item.sequence);
        dst.extend_from_slice(&item.payload);
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

        let mut message = Self::decode_wire_message(frame)?;
        Self::validate_wire_metadata(&message)?;

        if let Some(cipher) = self.state.session_cipher() {
            if Self::is_auth(message.message_type) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authentication frames are forbidden after session establishment",
                ));
            }
            cipher
                .open_in_place(
                    message.message_type,
                    message.compression,
                    message.sequence,
                    &mut message.payload,
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
            let sequence = cipher
                .seal_in_place(item.message_type, item.compression, &mut item.payload)
                .map_err(|e| Self::io_error("TCP 帧加密失败", e))?;
            item.sequence = sequence;
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

        Self::encode_wire_message(item, dst)
    }
}
