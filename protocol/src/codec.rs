use crate::message::{Message, MAX_MESSAGE_SIZE};
use bytes::{Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

/// Codec for proxy protocol messages using length-delimited framing.
/// Uses tokio-util's LengthDelimitedCodec for reliable message framing.
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

    fn decode(&mut self, src: &mut BytesMut) -> std::result::Result<Option<Self::Item>, Self::Error> {
        // Use LengthDelimitedCodec to handle framing
        match self.inner.decode(src)? {
            Some(frame) => {
                // Deserialize the message from the frame
                let message: Message = serde_json::from_slice(&frame).map_err(|e| {
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

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> std::result::Result<(), Self::Error> {
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

pub type ProxyEncoder = ProxyCodec;
pub type ProxyDecoder = ProxyCodec;
