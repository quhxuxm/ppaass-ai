use super::{
    UDP_MAX_DATAGRAM_SIZE, UDP_MAX_FRAGMENT_PLAINTEXT, UDP_MAX_FRAGMENTS, UDP_MAX_MESSAGE_SIZE,
    UDP_TRANSPORT_HEADER_LEN, UDP_TRANSPORT_MAGIC, UDP_TRANSPORT_VERSION, UdpSessionId,
    UdpTransportError, UdpTransportResult,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UdpPacketKind {
    AuthInit = 1,
    AuthOk = 2,
    Encrypted = 3,
}

impl TryFrom<u8> for UdpPacketKind {
    type Error = UdpTransportError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AuthInit),
            2 => Ok(Self::AuthOk),
            3 => Ok(Self::Encrypted),
            _ => Err(UdpTransportError::InvalidPacketKind(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPacketHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub kind: UdpPacketKind,
    pub session_id: UdpSessionId,
    pub seq: u64,
    pub message_id: u64,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub total_len: u32,
}

impl UdpPacketHeader {
    pub fn new(
        kind: UdpPacketKind,
        session_id: UdpSessionId,
        seq: u64,
        message_id: u64,
        fragment_index: u16,
        fragment_count: u16,
        total_len: u32,
    ) -> Self {
        Self {
            magic: UDP_TRANSPORT_MAGIC,
            version: UDP_TRANSPORT_VERSION,
            kind,
            session_id,
            seq,
            message_id,
            fragment_index,
            fragment_count,
            total_len,
        }
    }

    pub fn validate(&self) -> UdpTransportResult<()> {
        if self.magic != UDP_TRANSPORT_MAGIC {
            return Err(UdpTransportError::InvalidMagic);
        }
        if self.version != UDP_TRANSPORT_VERSION {
            return Err(UdpTransportError::UnsupportedVersion(self.version));
        }
        if self.kind != UdpPacketKind::Encrypted
            && (self.seq != 0
                || self.message_id != 0
                || self.fragment_index != 0
                || self.fragment_count != 1)
        {
            return Err(UdpTransportError::InvalidHeader(
                "authentication packets cannot be sequenced or fragmented",
            ));
        }

        let count = usize::from(self.fragment_count);
        let index = usize::from(self.fragment_index);
        let total_len = self.total_len as usize;
        if count == 0 {
            return Err(UdpTransportError::InvalidHeader(
                "fragment_count must be non-zero",
            ));
        }
        if count > UDP_MAX_FRAGMENTS {
            return Err(UdpTransportError::TooManyFragments(count));
        }
        if index >= count {
            return Err(UdpTransportError::InvalidHeader(
                "fragment_index is outside fragment_count",
            ));
        }
        let max_total_len = match self.kind {
            UdpPacketKind::Encrypted => UDP_MAX_MESSAGE_SIZE,
            UdpPacketKind::AuthInit | UdpPacketKind::AuthOk => {
                UDP_MAX_DATAGRAM_SIZE - UDP_TRANSPORT_HEADER_LEN
            }
        };
        if total_len > max_total_len {
            return Err(UdpTransportError::MessageTooLarge(total_len));
        }
        if total_len == 0 && count != 1 {
            return Err(UdpTransportError::InvalidHeader(
                "an empty message must have exactly one fragment",
            ));
        }
        if total_len > 0 && count > total_len {
            return Err(UdpTransportError::InvalidHeader(
                "non-empty fragments cannot outnumber plaintext bytes",
            ));
        }
        if self.kind == UdpPacketKind::Encrypted && total_len > count * UDP_MAX_FRAGMENT_PLAINTEXT {
            return Err(UdpTransportError::InvalidHeader(
                "fragment_count cannot carry total_len",
            ));
        }
        Ok(())
    }

    /// Encode the complete fixed-size header. These exact bytes are used as AEAD AAD.
    pub fn encode(&self) -> UdpTransportResult<[u8; UDP_TRANSPORT_HEADER_LEN]> {
        self.validate()?;
        let mut out = [0_u8; UDP_TRANSPORT_HEADER_LEN];
        out[0..4].copy_from_slice(&self.magic);
        out[4] = self.version;
        out[5] = self.kind as u8;
        out[6..22].copy_from_slice(&self.session_id);
        out[22..30].copy_from_slice(&self.seq.to_be_bytes());
        out[30..38].copy_from_slice(&self.message_id.to_be_bytes());
        out[38..40].copy_from_slice(&self.fragment_index.to_be_bytes());
        out[40..42].copy_from_slice(&self.fragment_count.to_be_bytes());
        out[42..46].copy_from_slice(&self.total_len.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> UdpTransportResult<Self> {
        if bytes.len() < UDP_TRANSPORT_HEADER_LEN {
            return Err(UdpTransportError::DatagramTooShort(bytes.len()));
        }

        let header = Self {
            magic: bytes[0..4].try_into().expect("fixed header slice"),
            version: bytes[4],
            kind: UdpPacketKind::try_from(bytes[5])?,
            session_id: bytes[6..22].try_into().expect("fixed header slice"),
            seq: u64::from_be_bytes(bytes[22..30].try_into().expect("fixed header slice")),
            message_id: u64::from_be_bytes(bytes[30..38].try_into().expect("fixed header slice")),
            fragment_index: u16::from_be_bytes(
                bytes[38..40].try_into().expect("fixed header slice"),
            ),
            fragment_count: u16::from_be_bytes(
                bytes[40..42].try_into().expect("fixed header slice"),
            ),
            total_len: u32::from_be_bytes(bytes[42..46].try_into().expect("fixed header slice")),
        };
        header.validate()?;
        Ok(header)
    }
}
