use protocol::crypto::{
    RsaKeyPair, encrypt_oaep_sha256, encrypt_oaep_sha256_labelled, verify_pss_sha256,
};

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

#[test]
fn labelled_oaep_requires_the_exact_tcp_context_label_and_key() {
    let (pair, public_key) = key_pair_and_public_key();
    let (wrong_pair, _) = key_pair_and_public_key();
    let plaintext = b"tcp v2 session secret";
    let ciphertext =
        encrypt_oaep_sha256_labelled(&public_key, "ppaass/tcp-test/v2", plaintext).unwrap();

    assert_eq!(
        pair.decrypt_oaep_sha256_labelled("ppaass/tcp-test/v2", &ciphertext)
            .unwrap(),
        plaintext
    );
    assert!(
        pair.decrypt_oaep_sha256_labelled("ppaass/tcp-test/v1", &ciphertext)
            .is_err()
    );
    assert!(
        wrong_pair
            .decrypt_oaep_sha256_labelled("ppaass/tcp-test/v2", &ciphertext)
            .is_err()
    );

    let short_ciphertext = &ciphertext[..ciphertext.len() - 1];
    assert!(
        pair.decrypt_oaep_sha256_labelled("ppaass/tcp-test/v2", short_ciphertext)
            .is_err()
    );
}
