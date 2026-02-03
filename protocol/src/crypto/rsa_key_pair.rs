use crate::error::{ProtocolError, Result};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    rand_core::OsRng,
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
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

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        self.public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, data)
            .map_err(|e| ProtocolError::Encryption(e.to_string()))
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.private_key
            .decrypt(Pkcs1v15Encrypt, data)
            .map_err(|e| ProtocolError::Decryption(e.to_string()))
    }

    /// Encrypt data with private key (can be decrypted with public key)
    /// This uses raw RSA private key operation: c = m^d mod n
    pub fn encrypt_with_private_key(&self, data: &[u8]) -> Result<Vec<u8>> {
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        use rsa::BigUint;

        // Add PKCS#1 v1.5 signature padding: 0x00 0x01 [0xFF padding] 0x00 [data]
        let key_size = self.private_key.size();
        if data.len() > key_size - 11 {
            return Err(ProtocolError::Encryption(
                "Data too large for key size".to_string(),
            ));
        }

        let padding_len = key_size - data.len() - 3;
        let mut padded = Vec::with_capacity(key_size);
        padded.push(0x00);
        padded.push(0x01);
        padded.extend(std::iter::repeat_n(0xFF, padding_len));
        padded.push(0x00);
        padded.extend_from_slice(data);

        // Raw RSA private key operation: c = m^d mod n
        let m = BigUint::from_bytes_be(&padded);
        let d = self.private_key.d();
        let n = self.private_key.n();

        let c = m.modpow(d, n);

        // Ensure output is key_size bytes (pad with leading zeros if needed)
        let c_bytes = c.to_bytes_be();
        let mut result = vec![0u8; key_size - c_bytes.len()];
        result.extend(c_bytes);

        Ok(result)
    }
}
