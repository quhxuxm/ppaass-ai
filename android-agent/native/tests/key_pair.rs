use android_agent::validate_key_pair;
use protocol::RsaKeyPair;

#[test]
fn managed_key_pair_validation_rejects_mismatched_or_invalid_pem() {
    let first = RsaKeyPair::generate(2048).unwrap();
    let second = RsaKeyPair::generate(2048).unwrap();
    let first_private = first.private_key_to_pem().unwrap();
    let first_public = first.public_key_to_pem().unwrap();
    let second_public = second.public_key_to_pem().unwrap();

    assert!(validate_key_pair(&first_private, &first_public));
    assert!(!validate_key_pair(&first_private, &second_public));
    assert!(!validate_key_pair("not a private key", &first_public));
}
