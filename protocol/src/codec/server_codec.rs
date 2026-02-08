use crate::message::{MAX_MESSAGE_SIZE, Message, MessageType, ProxyRequest, ProxyResponse};
use bytes::{Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

pub struct ServerCodec {
    inner: LengthDelimitedCodec,
}

impl ServerCodec {
    pub fn new() -> Self {
        let inner = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_MESSAGE_SIZE)
            .length_field_type::<u32>()
            .big_endian()
            .new_codec();
        Self { inner }
    }
}

impl Default for ServerCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for ServerCodec {
    type Item = ProxyRequest;
    type Error = io::Error;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src)? {
            Some(frame) => {
                let message: Message = bitcode::deserialize(&frame).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to deserialize message: {}", e),
                    )
                })?;
                let request: ProxyRequest =
                    bitcode::deserialize(&message.payload).map_err(|e| {
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

    fn encode(
        &mut self,
        item: ProxyResponse,
        dst: &mut BytesMut,
    ) -> std::result::Result<(), Self::Error> {
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

        let data = bitcode::serialize(&message).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize message: {}", e),
            )
        })?;

        self.inner.encode(Bytes::from(data), dst)
    }
}
