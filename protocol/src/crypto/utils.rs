use crate::error::{ProtocolError, Result};
use rsa::{
    Oaep, Pss, RsaPublicKey,
    rand_core::OsRng,
    sha2::{Digest as RsaDigest, Sha256 as RsaSha256},
    traits::PublicKeyParts,
};
use sha2::{Digest, Sha256};

pub fn hash_password(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    hasher.finalize().to_vec()
}

/// Verify an RSASSA-PSS-SHA256 signature over `message`.
pub fn verify_pss_sha256(
    public_key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    validate_rsa_public_key_size(public_key)?;
    if signature.len() != public_key.size() {
        return Err(ProtocolError::AuthenticationFailed(
            "invalid RSA-PSS signature length".to_string(),
        ));
    }
    let digest = RsaSha256::digest(message);
    public_key
        .verify(Pss::new::<RsaSha256>(), &digest, signature)
        .map_err(|e| ProtocolError::AuthenticationFailed(e.to_string()))
}

/// Encrypt plaintext using RSAES-OAEP with SHA-256 for OAEP and MGF1.
pub fn encrypt_oaep_sha256(public_key: &RsaPublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    validate_rsa_public_key_size(public_key)?;
    let mut rng = OsRng;
    public_key
        .encrypt(&mut rng, Oaep::new::<RsaSha256>(), plaintext)
        .map_err(|e| ProtocolError::Encryption(e.to_string()))
}

pub fn encrypt_oaep_sha256_labelled(
    public_key: &RsaPublicKey,
    label: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    validate_rsa_public_key_size(public_key)?;
    let mut rng = OsRng;
    public_key
        .encrypt(
            &mut rng,
            Oaep::new_with_label::<RsaSha256, _>(label),
            plaintext,
        )
        .map_err(|e| ProtocolError::Encryption(e.to_string()))
}

pub fn validate_rsa_public_key_size(public_key: &RsaPublicKey) -> Result<()> {
    const MIN_RSA_MODULUS_BYTES: usize = 256;
    const MAX_RSA_MODULUS_BYTES: usize = 1_024;
    if !(MIN_RSA_MODULUS_BYTES..=MAX_RSA_MODULUS_BYTES).contains(&public_key.size()) {
        return Err(ProtocolError::InvalidKey(
            "RSA key size must be between 2048 and 8192 bits".to_string(),
        ));
    }
    Ok(())
}
