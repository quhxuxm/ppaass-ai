//! Tool to generate RSA keys for demo configuration

use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    rand_core::OsRng,
};

fn main() {
    println!("Generating RSA-2048 key pair for demo user...\n");

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate key");
    let public_key = private_key.to_public_key();

    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to encode private key");

    let public_key_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .expect("Failed to encode public key");

    println!("=== PRIVATE KEY (save to keys/user1.pem) ===");
    println!("{}", private_key_pem.as_str());

    println!("\n=== PUBLIC KEY (for users.toml) ===");
    println!("{}", public_key_pem);
}
