use crate::error::{ProtocolError, Result};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey, rand_core::OsRng, traits::PublicKeyParts};
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

/// 解密由对应私钥加密的数据。
/// 注意：标准 RSA 是公钥加密、私钥解密。
/// 对于反向流程（私钥加密、公钥解密），这里采用一个变通方案：
/// agent 使用公钥按标准 RSA 加密 AES 密钥，
/// proxy 再使用私钥解密。
///
/// 但按需求，agent 持有私钥，proxy 持有公钥。
/// 因此需要 agent 使用私钥签名/加密，proxy 使用公钥验证/解密。
/// 实现上让 agent 使用标准加密（需要公钥），
/// 由于 agent 只有私钥，因此从私钥派生公钥。
pub fn decrypt_with_public_key(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    // RSA 不支持直接用公钥解密。
    // 需求想要的是：agent 用私钥加密，proxy 用公钥解密。
    // 这本质上类似 RSA 签名验证。
    //
    // 为了得到可工作的实现，这里使用另一种方式：
    // AES 密钥由 agent 使用其私钥加密（本质上是签名），
    // proxy 使用公钥验证并取出原始数据。
    //
    // 但标准 RSA 库不会暴露原始的“公钥解密”接口。
    // 实用变通方案：直接使用原始 RSA 原语。

    // 原始 RSA：m = c^e mod n（公钥操作，通常用于加密）
    // 用公钥“解密”时，同样执行：m = c^e mod n
    let c = BigUint::from_bytes_be(data);
    let e = public_key.e();
    let n = public_key.n();

    let m = c.modpow(e, n);
    let m_bytes = m.to_bytes_be();

    // 移除 PKCS#1 v1.5 填充（0x00 0x01 [0xFF 填充字节] 0x00 [数据]）
    // 签名填充格式：0x00 0x01 [0xFF 填充] 0x00 [数据]
    if m_bytes.len() < 11 {
        return Err(ProtocolError::Decryption("Invalid padding".to_string()));
    }

    // 查找填充后的 0x00 分隔符
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
