use crate::message::{MAX_MESSAGE_SIZE, Message, MessageType, ProxyRequest, ProxyResponse};
use bytes::{Bytes, BytesMut};
use std::{io, result::Result};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};
use tracing::error;

pub struct AgentCodec {
    inner: LengthDelimitedCodec,
}

impl AgentCodec {
    pub fn new() -> Self {
        let inner = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_MESSAGE_SIZE)
            .length_field_type::<u32>()
            .big_endian()
            .new_codec();
        Self { inner }
    }
}

impl Default for AgentCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for AgentCodec {
    type Item = ProxyResponse;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src)? {
            Some(frame) => {
                let message: Message = bitcode::deserialize(&frame).map_err(|e| {
                    error!("Failed to deserialize message: {}", e);
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to deserialize message: {}", e),
                    )
                })?;
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

        let data = bitcode::serialize(&message).map_err(|e| {
            error!("Serialization failed: {}", e);
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize message: {}", e),
            )
        })?;

        self.inner.encode(Bytes::from(data), dst)
    }
}
