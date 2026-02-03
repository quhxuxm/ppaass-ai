use super::{CipherState, ProxyCodec};
use crate::message::{Message, MessageType, ProxyRequest, ProxyResponse};
use bytes::BytesMut;
use std::io;
use std::sync::Arc;
use tokio_util::codec::{Decoder, Encoder};

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
                let request: ProxyRequest = bitcode::deserialize(&message.payload).map_err(|e| {
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

        let payload = bitcode::serialize(&item).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize proxy response: {}", e),
            )
        })?;

        let message = Message::new(message_type, payload);
        self.inner.encode(message, dst)
    }
}
