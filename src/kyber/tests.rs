use super::*;

#[test]
fn test_kyber_key_generation() {
    // Test key generation for each variant
    for variant in [
        KyberVariant::Kyber512,
        KyberVariant::Kyber768,
        KyberVariant::Kyber1024,
    ]
    .iter()
    {
        let key_pair = KyberKeyPair::generate(*variant).unwrap();
        assert!(!key_pair.public_key.is_empty());
        assert!(!key_pair.secret_key.is_empty());
    }
}

#[test]
fn test_kyber_encapsulation_decapsulation() {
    // Test the full encapsulation/decapsulation cycle
    let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
    let (ciphertext, shared_secret1) = key_pair.encapsulate().unwrap();

    let shared_secret2 = key_pair.decapsulate(&ciphertext).unwrap();

    // Verify both shared secrets match
    assert_eq!(shared_secret1, shared_secret2);
}

#[test]
fn test_kyber_public_key_operations() {
    // Test public key operations
    let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
    let public_key = key_pair.public_key();

    // Test encapsulation with public key
    let (ciphertext, shared_secret1) = public_key.encapsulate().unwrap();

    // Verify decapsulation works with the original key pair
    let shared_secret2 = key_pair.decapsulate(&ciphertext).unwrap();

    // Verify both shared secrets match
    assert_eq!(shared_secret1, shared_secret2);
}
