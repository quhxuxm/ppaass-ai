use crate::{Error, Result};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
};
use sha2::{Digest, Sha256};

pub const RSA_KEY_SIZE: usize = 2048;
pub const AES_KEY_SIZE: usize = 32;
pub const AES_NONCE_SIZE: usize = 12;

/// Generate RSA key pair
pub fn generate_rsa_keypair() -> Result<(String, String)> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE)
        .map_err(|e| Error::Rsa(format!("Failed to generate RSA private key: {}", e)))?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::Rsa(format!("Failed to encode private key: {}", e)))?;
    let public_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| Error::Rsa(format!("Failed to encode public key: {}", e)))?;

    Ok((public_pem, private_pem.to_string()))
}

/// Encrypt data with RSA public key
pub fn rsa_encrypt(public_key_pem: &str, data: &[u8]) -> Result<Vec<u8>> {
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| Error::Rsa(format!("Failed to parse public key: {}", e)))?;

    let mut rng = rand::thread_rng();
    let encrypted = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .map_err(|e| Error::Encryption(format!("RSA encryption failed: {}", e)))?;

    Ok(encrypted)
}

/// Decrypt data with RSA private key
pub fn rsa_decrypt(private_key_pem: &str, encrypted_data: &[u8]) -> Result<Vec<u8>> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| Error::Rsa(format!("Failed to parse private key: {}", e)))?;

    let decrypted = private_key
        .decrypt(Pkcs1v15Encrypt, encrypted_data)
        .map_err(|e| Error::Decryption(format!("RSA decryption failed: {}", e)))?;

    Ok(decrypted)
}

/// Generate AES key
pub fn generate_aes_key() -> [u8; AES_KEY_SIZE] {
    let mut key = [0u8; AES_KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt data with AES-256-GCM
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AES_KEY_SIZE {
        return Err(Error::Aes("Invalid AES key size".to_string()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::Aes(format!("Failed to create cipher: {}", e)))?;

    let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Encryption(format!("AES encryption failed: {}", e)))?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with AES-256-GCM
pub fn aes_decrypt(key: &[u8], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AES_KEY_SIZE {
        return Err(Error::Aes("Invalid AES key size".to_string()));
    }

    if ciphertext_with_nonce.len() < AES_NONCE_SIZE {
        return Err(Error::Aes("Ciphertext too short".to_string()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::Aes(format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(&ciphertext_with_nonce[..AES_NONCE_SIZE]);
    let ciphertext = &ciphertext_with_nonce[AES_NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| Error::Decryption(format!("AES decryption failed: {}", e)))?;

    Ok(plaintext)
}

/// Hash password with SHA-256
pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    BASE64.encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_encryption() {
        let (public_key, private_key) = generate_rsa_keypair().unwrap();
        let data = b"Hello, World!";

        let encrypted = rsa_encrypt(&public_key, data).unwrap();
        let decrypted = rsa_decrypt(&private_key, &encrypted).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aes_encryption() {
        let key = generate_aes_key();
        let data = b"Hello, World!";

        let encrypted = aes_encrypt(&key, data).unwrap();
        let decrypted = aes_decrypt(&key, &encrypted).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_password_hash() {
        let password = "test_password";
        let hash = hash_password(password);
        assert!(!hash.is_empty());
        assert_eq!(hash, hash_password(password));
    }
}
