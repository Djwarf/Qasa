use super::*;

#[test]
fn test_dilithium_key_generation() {
    // Test key generation for each variant
    for variant in [
        DilithiumVariant::Dilithium2,
        DilithiumVariant::Dilithium3,
        DilithiumVariant::Dilithium5,
    ]
    .iter()
    {
        let key_pair = DilithiumKeyPair::generate(*variant).unwrap();
        assert!(!key_pair.public_key.is_empty());
        assert!(!key_pair.secret_key.is_empty());
    }
}

#[test]
fn test_dilithium_sign_verify() {
    // Test the full sign/verify cycle
    let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
    let message = b"Test message for signing";

    let signature = key_pair.sign(message).unwrap();
    assert!(!signature.is_empty());

    let valid = key_pair.verify(message, &signature).unwrap();
    assert!(valid);
}

#[test]
fn test_dilithium_public_key_operations() {
    // Test public key operations
    let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
    let public_key = key_pair.public_key();
    let message = b"Test message for public key verification";

    let signature = key_pair.sign(message).unwrap();

    // Verify with public key
    let valid = public_key.verify(message, &signature).unwrap();
    assert!(valid);

    // Verify tampered message fails
    let tampered_message = b"Tampered message";
    let valid = public_key.verify(tampered_message, &signature).unwrap();
    assert!(!valid);
}

#[test]
fn test_lean_dilithium() {
    // Test the lean Dilithium implementation
    let mut lean = LeanDilithium::new(DilithiumVariant::Dilithium2);
    let key_pair = lean.generate_keypair().unwrap();

    let message = b"Test message for lean signing";
    let signature = lean.sign(message, &key_pair.secret_key).unwrap();

    let valid = lean
        .verify(message, &signature, &key_pair.public_key)
        .unwrap();
    assert!(valid);

    // Clean up resources
    lean.release_resources();
}
