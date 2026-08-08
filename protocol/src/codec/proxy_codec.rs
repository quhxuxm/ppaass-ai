use super::{CipherState, MessageCodec, data_packet_codec};
use crate::message::{Message, MessageType, ProxyRequest, ProxyResponse};
use bytes::BytesMut;
use std::io;
use std::sync::Arc;
use tokio_util::codec::{Decoder, Encoder};

pub struct ProxyCodec {
    inner: MessageCodec,
}

impl ProxyCodec {
    pub fn new(state: Arc<CipherState>) -> Self {
        Self {
            inner: MessageCodec::new(state),
        }
    }
}

impl Decoder for ProxyCodec {
    type Item = ProxyRequest;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src)? {
            Some(message) => {
                if message.message_type == MessageType::Data {
                    return data_packet_codec::decode(message.payload)
                        .map(ProxyRequest::Data)
                        .map(Some);
                }
                let request: ProxyRequest =
                    bitcode::deserialize(&message.payload).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Failed to deserialize proxy request: {}", e),
                        )
                    })?;
                let expected_type = match &request {
                    ProxyRequest::Auth(_) => MessageType::AuthRequest,
                    ProxyRequest::Connect(_) => MessageType::ConnectRequest,
                    ProxyRequest::Data(_) => MessageType::Data,
                };
                if message.message_type != expected_type {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "proxy request type does not match authenticated frame type",
                    ));
                }
                Ok(Some(request))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<ProxyResponse> for ProxyCodec {
    type Error = io::Error;

    fn encode(&mut self, item: ProxyResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let (message_type, payload) = match item {
            ProxyResponse::Data(packet) => (MessageType::Data, data_packet_codec::encode(packet)?),
            ProxyResponse::Error { message } => (MessageType::Error, message.into_bytes()),
            item => {
                let message_type = match &item {
                    ProxyResponse::Auth(_) => MessageType::AuthResponse,
                    ProxyResponse::Connect(_) => MessageType::ConnectResponse,
                    ProxyResponse::Data(_) | ProxyResponse::Error { .. } => unreachable!(),
                };
                let payload = bitcode::serialize(&item).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to serialize proxy response: {}", e),
                    )
                })?;
                (message_type, payload)
            }
        };

        let message = Message::new(message_type, payload);
        self.inner.encode(message, dst)
    }
}
