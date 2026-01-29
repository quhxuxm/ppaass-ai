use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{protocol::Message, Error, Result};

#[derive(Debug, Default, Clone, Copy)]
pub struct MessageCodec;

impl MessageCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Encoder<Message> for MessageCodec {
    type Error = Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<()> {
        let bytes = item.to_bytes()?;
        dst.reserve(bytes.len());
        dst.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < 4 {
            return Ok(None);
        }

        let len = u32::from_be_bytes(src[..4].try_into().unwrap()) as usize;
        if src.len() < 4 + len {
            return Ok(None);
        }

        src.advance(4);
        let payload = src.split_to(len);

        let mut frame = BytesMut::with_capacity(4 + len);
        frame.put_u32(len as u32);
        frame.extend_from_slice(&payload);

        let message = Message::from_bytes(frame.freeze())?;
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn encode_appends_length_prefixed_payload() {
        let mut codec = MessageCodec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(Message::Heartbeat { timestamp: 4242 }, &mut buf)
            .unwrap();

        assert!(buf.len() > 4);
        let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(len, buf.len() - 4);

        let decoded = Message::from_bytes(buf.freeze()).unwrap();
        match decoded {
            Message::Heartbeat { timestamp } => assert_eq!(timestamp, 4242),
            other => panic!("Unexpected message: {:?}", other),
        }
    }

    #[test]
    fn decode_returns_message_when_frame_complete() {
        let mut codec = MessageCodec::new();
        let mut frame = Message::AuthResponse {
            success: true,
            message: "ok".into(),
            session_id: Some("abc".into()),
        }
        .to_bytes()
        .unwrap();

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&mut frame);

        let decoded = codec.decode(&mut buf).unwrap();
        matches!(decoded, Some(Message::AuthResponse { success: true, .. }));
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_returns_none_when_payload_incomplete() {
        let mut codec = MessageCodec::new();
        let full = Message::Error {
            message: "boom".into(),
        }
        .to_bytes()
        .unwrap();

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&full[..full.len() - 2]);

        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), full.len() - 2);
    }

    #[test]
    fn decode_returns_error_for_invalid_json_payload() {
        let mut codec = MessageCodec::new();
        let mut buf = BytesMut::new();
        buf.put_u32(3);
        buf.extend_from_slice(b"foo");

        let err = codec.decode(&mut buf).unwrap_err();
        matches!(err, Error::Serialization(_));
    }
}
