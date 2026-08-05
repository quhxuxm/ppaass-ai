use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use proxy_registry::{PrivateKeyCipher, PrivateKeyCipherError};

const MASTER_SECRET: &str = "test-only-master-secret-with-at-least-32-bytes";

#[test]
fn encrypts_and_authenticates_private_keys() {
    let cipher = PrivateKeyCipher::new(MASTER_SECRET).unwrap();
    let encrypted = cipher.encrypt("alice", 1, "private-pem").unwrap();
    assert!(
        !encrypted
            .windows("private-pem".len())
            .any(|value| value == b"private-pem")
    );
    assert_eq!(
        cipher.decrypt("alice", 1, &encrypted).unwrap().as_str(),
        "private-pem"
    );
    assert!(cipher.decrypt("bob", 1, &encrypted).is_err());
    assert!(cipher.decrypt("alice", 2, &encrypted).is_err());
}

#[test]
fn rejects_short_master_secret() {
    assert!(matches!(
        PrivateKeyCipher::new("short"),
        Err(PrivateKeyCipherError::MasterSecretTooShort)
    ));
}

#[test]
fn verifier_is_an_authenticated_envelope_and_rejects_a_different_key() {
    let cipher = PrivateKeyCipher::new(MASTER_SECRET).unwrap();
    let verifier = cipher.create_verifier().unwrap();
    let envelope = URL_SAFE_NO_PAD.decode(&verifier).unwrap();
    assert!(envelope.len() > 32);
    assert_eq!(envelope[0], 1);
    cipher.verify_verifier(&verifier).unwrap();

    let other =
        PrivateKeyCipher::new("another-test-only-master-secret-with-at-least-32-bytes").unwrap();
    assert!(matches!(
        other.verify_verifier(&verifier),
        Err(PrivateKeyCipherError::VerifierMismatch)
    ));
    assert!(matches!(
        cipher.verify_verifier("not base64!"),
        Err(PrivateKeyCipherError::InvalidVerifier)
    ));
}
