use crate::message::{MAX_MESSAGE_SIZE, Message};
use bytes::{Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};
use tracing::error;

/// Codec for proxy protocol messages using length-delimited framing.
/// Wraps tokio-util's LengthDelimitedCodec for reliable message framing.
/// Handles serialization and deserialization only.
pub struct ProxyCodec {
    inner: LengthDelimitedCodec,
}

impl ProxyCodec {
    pub fn new() -> Self {
        let inner = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_MESSAGE_SIZE)
            .length_field_type::<u32>()
            .big_endian()
            .new_codec();
        Self { inner }
    }
}

impl Default for ProxyCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for ProxyCodec {
    type Item = Message;
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
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<Message> for ProxyCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = bitcode::serialize(&item).map_err(|e| {
            error!("Serialization failed: {}", e);
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize message: {}", e),
            )
        })?;
        self.inner.encode(Bytes::from(data), dst)
    }
}
