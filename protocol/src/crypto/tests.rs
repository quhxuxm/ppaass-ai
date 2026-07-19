use super::{RsaKeyPair, encrypt_oaep_sha256, verify_pss_sha256};

fn key_pair_and_public_key() -> (RsaKeyPair, rsa::RsaPublicKey) {
    let pair = RsaKeyPair::generate(2048).unwrap();
    let public_pem = pair.public_key_to_pem().unwrap();
    let public_key = RsaKeyPair::from_public_key_pem(&public_pem).unwrap();
    (pair, public_key)
}

#[test]
fn pss_sha256_rejects_message_and_signature_tampering() {
    let (pair, public_key) = key_pair_and_public_key();
    let message = b"native UDP authentication transcript";
    let signature = pair.sign_pss_sha256(message).unwrap();

    verify_pss_sha256(&public_key, message, &signature).unwrap();
    assert!(
        verify_pss_sha256(
            &public_key,
            b"native UDP authentication transcripu",
            &signature
        )
        .is_err()
    );

    let mut tampered_signature = signature;
    tampered_signature[17] ^= 0x80;
    assert!(verify_pss_sha256(&public_key, message, &tampered_signature).is_err());
}

#[test]
fn oaep_sha256_rejects_ciphertext_tampering() {
    let (pair, public_key) = key_pair_and_public_key();
    let plaintext = b"native UDP session secret";
    let ciphertext = encrypt_oaep_sha256(&public_key, plaintext).unwrap();

    assert_eq!(pair.decrypt_oaep_sha256(&ciphertext).unwrap(), plaintext);

    let mut tampered_ciphertext = ciphertext;
    tampered_ciphertext[29] ^= 0x40;
    assert!(pair.decrypt_oaep_sha256(&tampered_ciphertext).is_err());
}
