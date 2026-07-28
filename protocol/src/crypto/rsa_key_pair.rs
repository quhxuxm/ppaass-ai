use crate::error::{ProtocolError, Result};
use rsa::{
    Oaep, Pss, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    rand_core::OsRng,
    sha2::{Digest, Sha256},
    traits::PublicKeyParts,
};

pub struct RsaKeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaKeyPair {
    pub fn generate(bits: usize) -> Result<Self> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| ProtocolError::InvalidKey(e.to_string()))?;
        let public_key = private_key.to_public_key();

        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn from_private_key_pem(pem: &str) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| ProtocolError::InvalidKey(e.to_string()))?;
        let public_key = private_key.to_public_key();

        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn from_public_key_pem(pem: &str) -> Result<RsaPublicKey> {
        RsaPublicKey::from_public_key_pem(pem).map_err(|e| ProtocolError::InvalidKey(e.to_string()))
    }

    pub fn private_key_to_pem(&self) -> Result<String> {
        self.private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| ProtocolError::InvalidKey(e.to_string()))
    }

    pub fn public_key_to_pem(&self) -> Result<String> {
        self.public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| ProtocolError::InvalidKey(e.to_string()))
    }

    pub fn modulus_size(&self) -> usize {
        self.private_key.size()
    }

    /// Sign a transcript using RSASSA-PSS with SHA-256 and a 32-byte salt.
    pub fn sign_pss_sha256(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.validate_modulus_size()?;
        let digest = Sha256::digest(message);
        let mut rng = OsRng;
        self.private_key
            .sign_with_rng(&mut rng, Pss::new_blinded::<Sha256>(), &digest)
            .map_err(|e| ProtocolError::Encryption(e.to_string()))
    }

    /// Decrypt a ciphertext using RSAES-OAEP with SHA-256 for OAEP and MGF1.
    pub fn decrypt_oaep_sha256(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.validate_modulus_size()?;
        if ciphertext.len() != self.modulus_size() {
            return Err(ProtocolError::Decryption(
                "invalid OAEP ciphertext length".to_string(),
            ));
        }
        let mut rng = OsRng;
        self.private_key
            .decrypt_blinded(&mut rng, Oaep::new::<Sha256>(), ciphertext)
            .map_err(|e| ProtocolError::Decryption(e.to_string()))
    }

    pub fn decrypt_oaep_sha256_labelled(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.validate_modulus_size()?;
        if ciphertext.len() != self.modulus_size() {
            return Err(ProtocolError::Decryption(
                "invalid OAEP ciphertext length".to_string(),
            ));
        }
        let mut rng = OsRng;
        self.private_key
            .decrypt_blinded(
                &mut rng,
                Oaep::new_with_label::<Sha256, _>(label),
                ciphertext,
            )
            .map_err(|e| ProtocolError::Decryption(e.to_string()))
    }

    fn validate_modulus_size(&self) -> Result<()> {
        if !(256..=1_024).contains(&self.modulus_size()) {
            return Err(ProtocolError::InvalidKey(
                "RSA key size must be between 2048 and 8192 bits".to_string(),
            ));
        }
        Ok(())
    }
}
