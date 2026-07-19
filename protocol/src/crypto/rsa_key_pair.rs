use crate::error::{ProtocolError, Result};
use rsa::{
    Oaep, Pkcs1v15Encrypt, Pss, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    rand_core::OsRng,
    sha2::{Digest, Sha256},
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

    /// Sign a message using RSASSA-PSS with SHA-256 and the standard 32-byte
    /// salt length. This API is intentionally separate from the legacy raw
    /// private-key operation used by the original TCP authentication protocol.
    pub fn sign_pss_sha256(&self, message: &[u8]) -> Result<Vec<u8>> {
        let digest = Sha256::digest(message);
        let mut rng = OsRng;
        self.private_key
            .sign_with_rng(&mut rng, Pss::new::<Sha256>(), &digest)
            .map_err(|e| ProtocolError::Encryption(e.to_string()))
    }

    /// Decrypt a ciphertext using RSAES-OAEP with SHA-256 for both OAEP and
    /// MGF1. The original PKCS#1 v1.5 `decrypt` method remains unchanged.
    pub fn decrypt_oaep_sha256(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.private_key
            .decrypt(Oaep::new::<Sha256>(), ciphertext)
            .map_err(|e| ProtocolError::Decryption(e.to_string()))
    }

    /// 使用私钥加密数据（可用公钥解密）
    /// 这里使用原始 RSA 私钥操作：c = m^d mod n
    pub fn encrypt_with_private_key(&self, data: &[u8]) -> Result<Vec<u8>> {
        use rsa::BigUint;
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};

        // 添加 PKCS#1 v1.5 签名填充：0x00 0x01 [0xFF 填充] 0x00 [数据]
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

        // 原始 RSA 私钥操作：c = m^d mod n
        let m = BigUint::from_bytes_be(&padded);
        let d = self.private_key.d();
        let n = self.private_key.n();

        let c = m.modpow(d, n);

        // 确保输出为 key_size 字节（必要时用前导零填充）
        let c_bytes = c.to_bytes_be();
        let mut result = vec![0u8; key_size - c_bytes.len()];
        result.extend(c_bytes);

        Ok(result)
    }
}
