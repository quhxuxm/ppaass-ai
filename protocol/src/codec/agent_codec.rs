use super::{CipherState, MessageCodec, data_packet_codec};
use crate::message::{Message, MessageType, ProxyRequest, ProxyResponse};
use bytes::BytesMut;
use std::sync::Arc;
use std::{io, result::Result};
use tokio_util::codec::{Decoder, Encoder};
use tracing::error;

pub struct AgentCodec {
    inner: MessageCodec,
}

impl AgentCodec {
    pub fn new(state: Arc<CipherState>) -> Self {
        Self {
            inner: MessageCodec::new(state),
        }
    }
}

impl Decoder for AgentCodec {
    type Item = ProxyResponse;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src)? {
            Some(message) => {
                if message.message_type == MessageType::Data {
                    return data_packet_codec::decode(message.payload)
                        .map(ProxyResponse::Data)
                        .map(Some);
                }
                if message.message_type == MessageType::Error {
                    let message = String::from_utf8(message.payload).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid proxy error message")
                    })?;
                    return Ok(Some(ProxyResponse::Error { message }));
                }
                let response: ProxyResponse =
                    bitcode::deserialize(&message.payload).map_err(|e| {
                        error!("代理响应反序列化失败：{}", e);
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Failed to deserialize proxy response: {}", e),
                        )
                    })?;
                let expected_type = match &response {
                    ProxyResponse::Auth(_) => MessageType::AuthResponse,
                    ProxyResponse::Connect(_) => MessageType::ConnectResponse,
                    ProxyResponse::Data(_) => MessageType::Data,
                    ProxyResponse::Error { .. } => MessageType::Error,
                };
                if message.message_type != expected_type {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "proxy response type does not match authenticated frame type",
                    ));
                }
                Ok(Some(response))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<ProxyRequest> for AgentCodec {
    type Error = io::Error;

    fn encode(&mut self, item: ProxyRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let (message_type, payload) = match item {
            ProxyRequest::Data(packet) => (MessageType::Data, data_packet_codec::encode(packet)?),
            item => {
                let message_type = match &item {
                    ProxyRequest::Auth(_) => MessageType::AuthRequest,
                    ProxyRequest::Connect(_) => MessageType::ConnectRequest,
                    ProxyRequest::Data(_) => unreachable!(),
                };
                let payload = bitcode::serialize(&item).map_err(|e| {
                    error!("代理请求序列化失败：{}", e);
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to serialize proxy request: {}", e),
                    )
                })?;
                (message_type, payload)
            }
        };

        let message = Message::new(message_type, payload);
        self.inner.encode(message, dst)
    }
}
