use common::{ClientConnectionConfig, ProxyEndpointAffinity};
use protocol::RsaKeyPair;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

struct KeyConfig(String);

impl fmt::Debug for KeyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("KeyConfig")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl ClientConnectionConfig for KeyConfig {
    fn remote_addr(&self) -> String {
        "unused.invalid:1".to_string()
    }

    fn username(&self) -> String {
        "cache-test".to_string()
    }

    fn private_key_pem(&self) -> Result<String, String> {
        Ok(self.0.clone())
    }

    fn timeout_duration(&self) -> Duration {
        Duration::from_secs(1)
    }
}

#[test]
fn parsed_private_key_is_reused_for_identical_pem() {
    let generated = RsaKeyPair::generate(2048).unwrap();
    let config = KeyConfig(generated.private_key_to_pem().unwrap());

    let first = config.private_key_pair().unwrap();
    let second = config.private_key_pair().unwrap();

    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn proxy_affinity_keeps_successful_endpoint_first() {
    let affinity = ProxyEndpointAffinity::with_initial_index(0);
    let endpoints = vec![
        "proxy-a:443".to_string(),
        "proxy-b:443".to_string(),
        "proxy-c:443".to_string(),
    ];

    assert_eq!(affinity.ordered_candidates(&endpoints), endpoints);

    affinity.record_success(&endpoints, "proxy-b:443");

    assert_eq!(
        affinity.ordered_candidates(&endpoints),
        vec![
            "proxy-b:443".to_string(),
            "proxy-c:443".to_string(),
            "proxy-a:443".to_string(),
        ]
    );
}
