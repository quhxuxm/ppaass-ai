use protocol::RsaKeyPair;
use proxy_registry::PrivateKeyCipher;

pub(super) struct TestStoredKeys {
    pub public_key_pem: String,
    pub encrypted_private_key: Vec<u8>,
}

pub(super) async fn generate_test_stored_keys(
    cipher: &PrivateKeyCipher,
    username: &str,
    key_version: i64,
) -> TestStoredKeys {
    let pair = RsaKeyPair::generate(2048).unwrap();
    let public_key_pem = pair.public_key_to_pem().unwrap();
    let private_key_pem = pair.private_key_to_pem().unwrap();
    let encrypted_private_key = cipher
        .encrypt(username, key_version, &private_key_pem)
        .unwrap();
    TestStoredKeys {
        public_key_pem,
        encrypted_private_key,
    }
}
