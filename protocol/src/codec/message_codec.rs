use super::CipherState;
use crate::compression::{CompressionMode, compress, decompress};
use crate::message::{MAX_MESSAGE_SIZE, Message, MessageType, PROTOCOL_VERSION};
use bytes::{Bytes, BytesMut};
use std::fmt::Write as _;
use std::io;
use std::sync::Arc;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};
use tracing::error;

/// 启用压缩的最小负载大小（避免小消息产生额外开销）
const MIN_COMPRESSION_SIZE: usize = 64;
const LENGTH_PREFIX_BYTES: usize = 4;
const PROTOCOL_PREFIX_PREVIEW_BYTES: usize = 16;
const MIN_SUPPORTED_PROTOCOL_VERSION: u8 = 1;

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

    fn oversized_frame_error(src: &BytesMut) -> Option<io::Error> {
        if src.len() < LENGTH_PREFIX_BYTES {
            return None;
        }

        let declared_frame_len =
            u32::from_be_bytes(src[..LENGTH_PREFIX_BYTES].try_into().ok()?) as usize;
        if declared_frame_len <= MAX_MESSAGE_SIZE {
            return None;
        }

        let preview_len = src.len().min(PROTOCOL_PREFIX_PREVIEW_BYTES);
        let preview = &src[..preview_len];
        Some(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "frame size too big: declared_frame_len={} max_frame_len={} first_bytes_hex=\"{}\" first_bytes_ascii=\"{}\" hint=\"{}\"",
                declared_frame_len,
                MAX_MESSAGE_SIZE,
                hex_preview(preview),
                ascii_preview(preview),
                protocol_prefix_hint(preview)
            ),
        ))
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
        if let Some(err) = Self::oversized_frame_error(src) {
            return Err(err);
        }

        let frame = match self.inner.decode(src)? {
            Some(frame) => frame,
            None => return Ok(None),
        };

        let mut message: Message =
            bitcode::deserialize(&frame).map_err(|e| Self::io_error("消息反序列化失败", e))?;
        if !(MIN_SUPPORTED_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&message.version) {
            return Err(Self::io_error(
                "协议版本不匹配",
                format!(
                    "received={} supported={}..={}",
                    message.version, MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION
                ),
            ));
        }

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

fn protocol_prefix_hint(prefix: &[u8]) -> &'static str {
    if prefix.starts_with(b"GET ")
        || prefix.starts_with(b"POST ")
        || prefix.starts_with(b"HEAD ")
        || prefix.starts_with(b"PUT ")
        || prefix.starts_with(b"DELETE ")
        || prefix.starts_with(b"PATCH ")
        || prefix.starts_with(b"OPTIONS ")
        || prefix.starts_with(b"CONNECT ")
    {
        return "疑似 HTTP 请求；请检查浏览器或系统代理是否直接指向了 PPAASS proxy 端口";
    }

    if prefix.starts_with(b"PRI * HTTP/2.0") {
        return "疑似 HTTP/2 preface；请检查 HTTP 客户端是否直接指向了 PPAASS proxy 端口";
    }

    if prefix.len() >= 3 && prefix[0] == 0x16 && prefix[1] == 0x03 {
        return "疑似 TLS/HTTPS ClientHello；请检查 HTTPS 流量是否直接打到了 PPAASS proxy 端口";
    }

    if prefix.first() == Some(&0x05) {
        return "疑似 SOCKS5；请检查 SOCKS 客户端是否指向了远端 PPAASS proxy，而不是本地 agent";
    }

    if prefix.starts_with(b"SSH-") {
        return "疑似 SSH；请检查 PPAASS proxy 是否监听在预期端口";
    }

    "首包不是有效的 PPAASS 长度分隔协议帧；请检查 endpoint、端口以及 agent/proxy 版本是否匹配"
}

fn hex_preview(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{AuthRequest, AuthResponse, ProxyRequest, ProxyResponse};
    use crate::{AgentCodec, ProxyCodec};
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;

    #[test]
    fn oversized_frame_error_identifies_http_prefix() {
        let mut codec = MessageCodec::default();
        let mut src = BytesMut::from(&b"GET / HTTP/1.1\r\n"[..]);

        let err = codec.decode(&mut src).expect_err("HTTP prefix should fail");
        let message = err.to_string();

        assert!(message.contains("frame size too big"));
        assert!(message.contains("declared_frame_len=1195725856"));
        assert!(message.contains("first_bytes_ascii=\"GET / HTTP/1.1..\""));
        assert!(message.contains("疑似 HTTP 请求"));
    }

    #[test]
    fn oversized_frame_error_identifies_tls_prefix() {
        let mut codec = MessageCodec::default();
        let mut src = BytesMut::from(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01][..]);

        let err = codec.decode(&mut src).expect_err("TLS prefix should fail");
        let message = err.to_string();

        assert!(message.contains("frame size too big"));
        assert!(message.contains("疑似 TLS/HTTPS ClientHello"));
    }

    #[test]
    fn decode_rejects_protocol_version_mismatch() {
        let mut encoder = MessageCodec::default();
        let mut decoder = MessageCodec::default();
        let mut src = BytesMut::new();
        let mut message = Message::new(MessageType::Data, b"payload".to_vec());
        message.version = PROTOCOL_VERSION.saturating_add(1);

        encoder.encode(message, &mut src).unwrap();

        let err = decoder
            .decode(&mut src)
            .expect_err("version mismatch should fail");
        let message = err.to_string();

        assert!(message.contains("协议版本不匹配"));
        assert!(message.contains(&format!(
            "supported={MIN_SUPPORTED_PROTOCOL_VERSION}..={PROTOCOL_VERSION}"
        )));
    }

    #[test]
    fn decode_accepts_legacy_protocol_version() {
        let mut encoder = MessageCodec::default();
        let mut decoder = MessageCodec::default();
        let mut src = BytesMut::new();
        let mut message = Message::new(MessageType::Data, b"payload".to_vec());
        message.version = MIN_SUPPORTED_PROTOCOL_VERSION;

        encoder.encode(message, &mut src).unwrap();
        let decoded = decoder.decode(&mut src).unwrap().unwrap();

        assert_eq!(decoded.version, MIN_SUPPORTED_PROTOCOL_VERSION);
        assert_eq!(decoded.payload, b"payload");
    }

    #[test]
    fn agent_and_proxy_codecs_roundtrip_auth_messages() {
        let mut agent_encoder = AgentCodec::new(None);
        let mut proxy_decoder = ProxyCodec::new(None);
        let mut request_buf = BytesMut::new();
        let request = ProxyRequest::Auth(AuthRequest {
            username: "user1".to_string(),
            timestamp: 123,
            encrypted_aes_key: vec![1, 2, 3, 4],
        });

        agent_encoder
            .encode(request.clone(), &mut request_buf)
            .unwrap();
        let decoded_request = proxy_decoder.decode(&mut request_buf).unwrap().unwrap();

        assert!(matches!(decoded_request, ProxyRequest::Auth(_)));

        let mut proxy_encoder = ProxyCodec::new(None);
        let mut agent_decoder = AgentCodec::new(None);
        let mut response_buf = BytesMut::new();
        let response = ProxyResponse::Auth(AuthResponse {
            success: true,
            message: "ok".to_string(),
            session_id: Some("session-1".to_string()),
        });

        proxy_encoder
            .encode(response.clone(), &mut response_buf)
            .unwrap();
        let decoded_response = agent_decoder.decode(&mut response_buf).unwrap().unwrap();

        assert!(matches!(decoded_response, ProxyResponse::Auth(_)));
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

        let data = bitcode::serialize(&item).map_err(|e| Self::io_error("消息序列化失败", e))?;
        self.inner.encode(Bytes::from(data), dst)
    }
}
