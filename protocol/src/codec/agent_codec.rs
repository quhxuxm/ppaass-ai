use super::{CipherState, ProxyCodec};
use crate::message::{Message, MessageType, ProxyRequest, ProxyResponse};
use bytes::BytesMut;
use std::io;
use std::sync::Arc;
use tokio_util::codec::{Decoder, Encoder};

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
                let response: ProxyResponse = bitcode::deserialize(&message.payload).map_err(|e| {
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

        let payload = bitcode::serialize(&item).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize proxy request: {}", e),
            )
        })?;

        let message = Message::new(message_type, payload);
        self.inner.encode(message, dst)
    }
}
