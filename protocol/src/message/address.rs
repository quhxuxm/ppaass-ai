use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Address {
    Domain { host: String, port: u16 },
    Ipv4 { addr: [u8; 4], port: u16 },
    Ipv6 { addr: [u8; 16], port: u16 },
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::Domain { port, .. } => *port,
            Address::Ipv4 { port, .. } => *port,
            Address::Ipv6 { port, .. } => *port,
        }
    }
}
