use crate::error::{ProtocolError, Result};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    rand_core::{OsRng, RngCore},
};
use sha2::{Digest, Sha256};

const AES_KEY_SIZE: usize = 32; // 256 bits
const NONCE_SIZE: usize = 12; // 96 bits for GCM

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
        use rsa::BigUint;
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};

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

    use rsa::BigUint;
    use rsa::traits::PublicKeyParts;

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

pub struct AesGcmCipher {
    key: [u8; AES_KEY_SIZE],
}

impl AesGcmCipher {
    pub fn new() -> Self {
        let mut key = [0u8; AES_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn from_key(key: [u8; AES_KEY_SIZE]) -> Self {
        Self { key }
    }

    pub fn key(&self) -> &[u8; AES_KEY_SIZE] {
        &self.key
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| ProtocolError::Encryption(e.to_string()))?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE {
            return Err(ProtocolError::Decryption(
                "Data too short to contain nonce".to_string(),
            ));
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let ciphertext = &data[NONCE_SIZE..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| ProtocolError::Decryption(e.to_string()))
    }
}

impl Default for AesGcmCipher {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CryptoManager {
    rsa_keypair: Option<RsaKeyPair>,
    aes_cipher: Option<AesGcmCipher>,
}

impl CryptoManager {
    pub fn new() -> Self {
        Self {
            rsa_keypair: None,
            aes_cipher: None,
        }
    }

    pub fn with_rsa_keypair(mut self, keypair: RsaKeyPair) -> Self {
        self.rsa_keypair = Some(keypair);
        self
    }

    pub fn with_aes_cipher(mut self, cipher: AesGcmCipher) -> Self {
        self.aes_cipher = Some(cipher);
        self
    }

    pub fn set_aes_cipher(&mut self, cipher: AesGcmCipher) {
        self.aes_cipher = Some(cipher);
    }

    pub fn rsa_encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.rsa_keypair
            .as_ref()
            .ok_or_else(|| ProtocolError::InvalidKey("RSA keypair not set".to_string()))?
            .encrypt(data)
    }

    pub fn rsa_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.rsa_keypair
            .as_ref()
            .ok_or_else(|| ProtocolError::InvalidKey("RSA keypair not set".to_string()))?
            .decrypt(data)
    }

    pub fn aes_encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.aes_cipher
            .as_ref()
            .ok_or_else(|| ProtocolError::InvalidKey("AES cipher not set".to_string()))?
            .encrypt(data)
    }

    pub fn aes_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.aes_cipher
            .as_ref()
            .ok_or_else(|| ProtocolError::InvalidKey("AES cipher not set".to_string()))?
            .decrypt(data)
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn hash_password(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    hasher.finalize().to_vec()
}
