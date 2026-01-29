// Simple utility to generate RSA keys for configuration
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};

fn main() {
    let mut rng = OsRng;

    println!("=== GENERATING RSA-2048 KEYS ===\n");

    // Proxy server keys
    println!("Generating proxy server RSA keys...");
    let proxy_private_key =
        RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate proxy private key");
    let proxy_public_key = RsaPublicKey::from(&proxy_private_key);

    let proxy_public_pem = proxy_public_key
        .to_public_key_pem(LineEnding::LF)
        .expect("Failed to encode proxy public key");
    let proxy_private_pem = proxy_private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to encode proxy private key");

    println!("\n=== PROXY SERVER PUBLIC KEY ===");
    println!("{}", proxy_public_pem);

    println!("=== PROXY SERVER PRIVATE KEY ===");
    println!("{}", &*proxy_private_pem);

    // Agent user keys
    println!("\n\nGenerating agent user RSA keys...");
    let agent_private_key =
        RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate agent private key");
    let agent_public_key = RsaPublicKey::from(&agent_private_key);

    let agent_public_pem = agent_public_key
        .to_public_key_pem(LineEnding::LF)
        .expect("Failed to encode agent public key");
    let agent_private_pem = agent_private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to encode agent private key");

    println!("\n=== AGENT USER PUBLIC KEY ===");
    println!("{}", agent_public_pem);

    println!("=== AGENT USER PRIVATE KEY ===");
    println!("{}", &*agent_private_pem);

    println!("\n\n=== INSTRUCTIONS ===");
    println!("1. Copy the PROXY SERVER PUBLIC KEY to agent.toml under 'proxy_rsa_public_key'");
    println!(
        "2. Copy the PROXY SERVER keys to proxy.toml under 'rsa_public_key' and 'rsa_private_key'"
    );
    println!(
        "3. Copy the AGENT USER keys to agent.toml under 'user.rsa_public_key' and 'user.rsa_private_key'"
    );
}
