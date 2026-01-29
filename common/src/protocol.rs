use crate::{Error, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

/// Message types exchanged between agent and proxy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    /// Authentication request from agent to proxy
    AuthRequest {
        username: String,
        password_hash: String,
        encrypted_aes_key: Vec<u8>, // AES key encrypted with proxy's public RSA key
    },
    /// Authentication response from proxy to agent
    AuthResponse {
        success: bool,
        message: String,
        session_id: Option<String>,
    },
    /// Data transfer message
    Data {
        session_id: String,
        encrypted_payload: Vec<u8>, // Data encrypted with AES
        target_addr: Option<String>,
        target_port: Option<u16>,
    },
    /// Response data from proxy to agent
    Response {
        session_id: String,
        encrypted_payload: Vec<u8>,
    },
    /// Connection close notification
    Close {
        session_id: String,
        reason: Option<String>,
    },
    /// Heartbeat to keep connection alive
    Heartbeat { timestamp: u64 },
    /// Error message
    Error { message: String },
}

impl Message {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Bytes> {
        let json = serde_json::to_vec(self)?;
        let len = json.len() as u32;

        let mut buf = BytesMut::with_capacity(4 + json.len());
        buf.put_u32(len);
        buf.put_slice(&json);

        Ok(buf.freeze())
    }

    /// Deserialize message from bytes
    pub fn from_bytes(mut bytes: Bytes) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(Error::Protocol("Message too short".to_string()));
        }

        let len = bytes.get_u32() as usize;
        if bytes.len() < len {
            return Err(Error::Protocol(format!(
                "Incomplete message: expected {} bytes, got {}",
                len,
                bytes.len()
            )));
        }

        let json_bytes = bytes.split_to(len);
        let message: Message = serde_json::from_slice(&json_bytes)?;

        Ok(message)
    }
}

/// SOCKS5 protocol structures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Socks5Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Socks5Command::Connect),
            0x02 => Ok(Socks5Command::Bind),
            0x03 => Ok(Socks5Command::UdpAssociate),
            _ => Err(Error::Protocol(format!(
                "Invalid SOCKS5 command: {}",
                value
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Socks5Address {
    IPv4([u8; 4]),
    IPv6([u8; 16]),
    Domain(String),
}

impl Socks5Address {
    pub fn to_string(&self) -> String {
        match self {
            Socks5Address::IPv4(octets) => {
                format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
            }
            Socks5Address::IPv6(segments) => {
                let parts: Vec<String> = segments
                    .chunks(2)
                    .map(|chunk| format!("{:02x}{:02x}", chunk[0], chunk[1]))
                    .collect();
                format!("[{}]", parts.join(":"))
            }
            Socks5Address::Domain(domain) => domain.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Socks5Request {
    pub command: Socks5Command,
    pub address: Socks5Address,
    pub port: u16,
}

/// HTTP proxy structures
#[derive(Debug, Clone)]
pub enum HttpMethod {
    Connect,
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
}

impl HttpMethod {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        match bytes {
            b"CONNECT" => Ok(HttpMethod::Connect),
            b"GET" => Ok(HttpMethod::Get),
            b"POST" => Ok(HttpMethod::Post),
            b"PUT" => Ok(HttpMethod::Put),
            b"DELETE" => Ok(HttpMethod::Delete),
            b"HEAD" => Ok(HttpMethod::Head),
            b"OPTIONS" => Ok(HttpMethod::Options),
            b"PATCH" => Ok(HttpMethod::Patch),
            _ => Err(Error::Protocol("Invalid HTTP method".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = Message::AuthRequest {
            username: "test_user".to_string(),
            password_hash: "hash123".to_string(),
            encrypted_aes_key: vec![1, 2, 3, 4],
        };

        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(bytes).unwrap();

        match decoded {
            Message::AuthRequest {
                username,
                password_hash,
                encrypted_aes_key,
            } => {
                assert_eq!(username, "test_user");
                assert_eq!(password_hash, "hash123");
                assert_eq!(encrypted_aes_key, vec![1, 2, 3, 4]);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
