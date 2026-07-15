use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Address {
    Domain { host: String, port: u16 },
    Ipv4 { addr: [u8; 4], port: u16 },
    Ipv6 { addr: [u8; 16], port: u16 },
    ProxyDns { port: u16 },
    UdpRelay,
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::Domain { port, .. } => *port,
            Address::Ipv4 { port, .. } => *port,
            Address::Ipv6 { port, .. } => *port,
            Address::ProxyDns { port } => *port,
            Address::UdpRelay => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Address;
    use std::collections::HashMap;

    #[test]
    fn equal_addresses_can_be_used_as_hash_map_keys() {
        let address = Address::Domain {
            host: "www.youtube.com".to_string(),
            port: 443,
        };
        let mut addresses = HashMap::new();
        addresses.insert(address.clone(), 7_u64);

        assert_eq!(addresses.get(&address), Some(&7));
        assert_eq!(addresses.len(), 1);
    }

    #[test]
    fn address_port_is_part_of_equality_and_hashing() {
        let https = Address::Ipv4 {
            addr: [142, 250, 72, 206],
            port: 443,
        };
        let dns = Address::Ipv4 {
            addr: [142, 250, 72, 206],
            port: 53,
        };
        let mut addresses = HashMap::new();
        addresses.insert(https, "https");
        addresses.insert(dns, "dns");

        assert_eq!(addresses.len(), 2);
    }
}
