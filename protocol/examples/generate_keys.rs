//! 为演示配置生成 RSA 密钥的工具

use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    rand_core::OsRng,
};

fn main() {
    println!("正在为演示用户生成 RSA-2048 密钥对...\n");

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate key");
    let public_key = private_key.to_public_key();

    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to encode private key");

    let public_key_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .expect("Failed to encode public key");

    println!("=== 私钥（保存到 keys/user1.pem）===");
    println!("{}", private_key_pem.as_str());

    println!("\n=== 公钥（用于 users.toml）===");
    println!("{}", public_key_pem);
}
