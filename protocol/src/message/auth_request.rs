use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub timestamp: i64,
    pub encrypted_aes_key: Vec<u8>, // AES key encrypted with RSA public key
}
