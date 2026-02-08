use super::{CipherState, CryptoMessageCodec};
use crate::message::{Message, MessageType, ProxyRequest, ProxyResponse};
use bytes::BytesMut;
use std::sync::Arc;
use std::{io, result::Result};
use tokio_util::codec::{Decoder, Encoder};
use tracing::error;

pub struct AgentCodec {
    inner: CryptoMessageCodec,
}

impl AgentCodec {
    pub fn new(state: Option<Arc<CipherState>>) -> Self {
        Self {
            inner: CryptoMessageCodec::new(state),
        }
    }
}

impl Decoder for AgentCodec {
    type Item = ProxyResponse;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src)? {
            Some(message) => {
                let response: ProxyResponse =
                    bitcode::deserialize(&message.payload).map_err(|e| {
                        error!("Failed to deserialize proxy response: {}", e);
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

    fn encode(&mut self, item: ProxyRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let message_type = match &item {
            ProxyRequest::Auth(_) => MessageType::AuthRequest,
            ProxyRequest::Connect(_) => MessageType::ConnectRequest,
            ProxyRequest::Data(_) => MessageType::Data,
        };

        let payload = bitcode::serialize(&item).map_err(|e| {
            error!("Failed to serialize proxy request: {}", e);
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize proxy request: {}", e),
            )
        })?;

        let message = Message::new(message_type, payload);
        self.inner.encode(message, dst)
    }
}
