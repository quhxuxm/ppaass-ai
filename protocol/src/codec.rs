use crate::message::{Message, MessageType, MAX_MESSAGE_SIZE};
use crate::message::{ProxyRequest, ProxyResponse};
use crate::crypto::AesGcmCipher;
use bytes::{Bytes, BytesMut};
use std::io;
use std::sync::{Arc, OnceLock};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

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

/// Codec for proxy protocol messages using length-delimited framing.
/// Uses tokio-util's LengthDelimitedCodec for reliable message framing.
/// Handles encryption and decryption transparently if a cipher is provided in the state.
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

    fn decode(&mut self, src: &mut BytesMut) -> std::result::Result<Option<Self::Item>, Self::Error> {
        // Use LengthDelimitedCodec to handle framing
        match self.inner.decode(src)? {
            Some(frame) => {
                // Deserialize the message from the frame
                let mut message: Message = serde_json::from_slice(&frame).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to deserialize message: {}", e),
                    )
                })?;

                // Decrypt payload if cipher is present and message type requires encryption
                if let Some(cipher) = self.state.cipher.get() {
                    if !matches!(message.message_type, MessageType::AuthRequest | MessageType::AuthResponse) {
                         let decrypted = cipher.decrypt(&message.payload).map_err(|e| {
                             io::Error::new(io::ErrorKind::InvalidData, format!("Decryption failed: {}", e))
                         })?;
                         message.payload = decrypted;
                    }
                }

                Ok(Some(message))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<Message> for ProxyCodec {
    type Error = io::Error;

    fn encode(&mut self, mut item: Message, dst: &mut BytesMut) -> std::result::Result<(), Self::Error> {
        // Encrypt payload if cipher is present and message type requires encryption
        {
            if let Some(cipher) = self.state.cipher.get() {
                if !matches!(item.message_type, MessageType::AuthRequest | MessageType::AuthResponse) {
                     let encrypted = cipher.encrypt(&item.payload).map_err(|e| {
                         io::Error::new(io::ErrorKind::InvalidData, format!("Encryption failed: {}", e))
                     })?;
                     item.payload = encrypted;
                }
            }
        }

        // Serialize the message
        let data = serde_json::to_vec(&item).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize message: {}", e),
            )
        })?;

        // Use LengthDelimitedCodec to handle framing
        self.inner.encode(Bytes::from(data), dst)
    }
}

pub struct AgentCodec {
    inner: ProxyCodec,
}

impl AgentCodec {
    pub fn new(state: Option<Arc<CipherState>>) -> Self {
        Self {
            inner: ProxyCodec::new(state),
        }
    }
}

impl Decoder for AgentCodec {
    type Item = ProxyResponse;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> std::result::Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src)? {
            Some(message) => {
                let response: ProxyResponse = serde_json::from_slice(&message.payload).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to deserialize proxy response: {}", e),
                    )
                })?;
                Ok(Some(response))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<ProxyRequest> for AgentCodec {
    type Error = io::Error;

    fn encode(&mut self, item: ProxyRequest, dst: &mut BytesMut) -> std::result::Result<(), Self::Error> {
        let message_type = match &item {
            ProxyRequest::Auth(_) => MessageType::AuthRequest,
            ProxyRequest::Connect(_) => MessageType::ConnectRequest,
            ProxyRequest::Data(_) => MessageType::Data,
        };

        let payload = serde_json::to_vec(&item).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize proxy request: {}", e),
            )
        })?;

        let message = Message::new(message_type, payload);
        self.inner.encode(message, dst)
    }
}

pub struct ServerCodec {
    inner: ProxyCodec,
}

impl ServerCodec {
    pub fn new(state: Option<Arc<CipherState>>) -> Self {
        Self {
            inner: ProxyCodec::new(state),
        }
    }
}

impl Decoder for ServerCodec {
    type Item = ProxyRequest;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> std::result::Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src)? {
            Some(message) => {
                let request: ProxyRequest = serde_json::from_slice(&message.payload).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to deserialize proxy request: {}", e),
                    )
                })?;
                Ok(Some(request))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<ProxyResponse> for ServerCodec {
    type Error = io::Error;

    fn encode(&mut self, item: ProxyResponse, dst: &mut BytesMut) -> std::result::Result<(), Self::Error> {
        let message_type = match &item {
            ProxyResponse::Auth(_) => MessageType::AuthResponse,
            ProxyResponse::Connect(_) => MessageType::ConnectResponse,
            ProxyResponse::Data(_) => MessageType::Data,
            ProxyResponse::Error { .. } => MessageType::Data, // Fallback, though Error unused in logic
        };

        let payload = serde_json::to_vec(&item).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize proxy response: {}", e),
            )
        })?;

        let message = Message::new(message_type, payload);
        self.inner.encode(message, dst)
    }
}

pub type ProxyEncoder = ProxyCodec;
pub type ProxyDecoder = ProxyCodec;
