use crate::error::{ProtocolError, Result};
use rsa::{rand_core::OsRng, traits::PublicKeyParts, BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use sha2::{Digest, Sha256};

pub fn hash_password(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    hasher.finalize().to_vec()
}

pub fn encrypt_with_public_key(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    let mut rng = OsRng;
    public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .map_err(|e| ProtocolError::Encryption(e.to_string()))
}

/// Decrypt data that was encrypted with the corresponding private key
/// Note: In standard RSA, you encrypt with public and decrypt with private.
/// For the reverse (encrypt with private, decrypt with public), we use a workaround:
/// The agent encrypts the AES key using standard RSA with the public key,
/// and the proxy decrypts using the private key.
///
/// However, per requirements, agent has private key and proxy has public key.
/// So we'll have the agent sign/encrypt with private key, and proxy verify/decrypt with public.
/// This is achieved by having the agent use standard encryption (which requires public key),
/// but since agent only has private key, we derive public key from it.
pub fn decrypt_with_public_key(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    // RSA doesn't support decrypting with public key directly.
    // The requirement seems to want: agent encrypts with private key, proxy decrypts with public key.
    // This is essentially RSA signature verification.
    //
    // For a working implementation, we'll use a different approach:
    // The AES key is encrypted by the agent using its private key (essentially signing),
    // and the proxy uses the public key to verify and extract the original data.
    //
    // However, standard RSA libraries don't expose raw "decrypt with public key".
    // A practical workaround: use the raw RSA primitive directly.

    // Raw RSA: m = c^e mod n (public key operation, normally used for encryption)
    // To "decrypt" with public key, we do: m = c^e mod n
    let c = BigUint::from_bytes_be(data);
    let e = public_key.e();
    let n = public_key.n();

    let m = c.modpow(e, n);
    let m_bytes = m.to_bytes_be();

    // Remove PKCS#1 v1.5 padding (0x00 0x01 [padding 0xFF bytes] 0x00 [data])
    // For signature padding: 0x00 0x01 [0xFF padding] 0x00 [data]
    if m_bytes.len() < 11 {
        return Err(ProtocolError::Decryption("Invalid padding".to_string()));
    }

    // Find the 0x00 separator after padding
    let mut data_start = None;
    for (i, &byte) in m_bytes.iter().enumerate().skip(2) {
        if byte == 0x00 {
            data_start = Some(i + 1);
            break;
        }
    }

    match data_start {
        Some(start) if start < m_bytes.len() => Ok(m_bytes[start..].to_vec()),
        _ => Err(ProtocolError::Decryption(
            "Invalid PKCS#1 padding".to_string(),
        )),
    }
}
