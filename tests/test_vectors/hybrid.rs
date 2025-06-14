//! Test vectors for hybrid cryptographic modes

use qasa::hybrid::hybrid_kem::{
    HybridKemKeyPair,
    HybridKemPublicKey,
    HybridKemVariant,
    ClassicalKemAlgorithm,
    PostQuantumKemAlgorithm,
};

use qasa::kyber::KyberVariant;
use qasa::bike::BikeVariant;
use qasa::error::CryptoResult;

/// Generate test vectors for hybrid KEM
pub fn generate_hybrid_kem_test_vectors() -> CryptoResult<Vec<u8>> {
    let mut result = Vec::new();
    
    // Test vector 1: X25519 + Kyber768
    let variant1 = HybridKemVariant {
        classical: ClassicalKemAlgorithm::X25519,
        post_quantum: PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber768),
    };
    
    // Generate key pair
    let key_pair1 = HybridKemKeyPair::generate(variant1)?;
    
    // Get public key
    let public_key1 = key_pair1.public_key()?;
    
    // Encapsulate
    let (ciphertext1, shared_secret1) = public_key1.encapsulate()?;
    
    // Serialize the test vector
    result.extend_from_slice(b"TEST_VECTOR_1\n");
    result.extend_from_slice(b"Variant: X25519 + Kyber768\n");
    
    let key_pair_bytes = key_pair1.to_bytes()?;
    result.extend_from_slice(b"KeyPair: ");
    for byte in &key_pair_bytes {
        result.extend_from_slice(format!("{:02x}", byte).as_bytes());
    }
    result.extend_from_slice(b"\n");
    
    let public_key_bytes = public_key1.to_bytes()?;
    result.extend_from_slice(b"PublicKey: ");
    for byte in &public_key_bytes {
        result.extend_from_slice(format!("{:02x}", byte).as_bytes());
    }
    result.extend_from_slice(b"\n");
    
    let ciphertext_bytes = ciphertext1.to_bytes()?;
    result.extend_from_slice(b"Ciphertext: ");
    for byte in &ciphertext_bytes {
        result.extend_from_slice(format!("{:02x}", byte).as_bytes());
    }
    result.extend_from_slice(b"\n");
    
    result.extend_from_slice(b"SharedSecret: ");
    for byte in &shared_secret1 {
        result.extend_from_slice(format!("{:02x}", byte).as_bytes());
    }
    result.extend_from_slice(b"\n\n");
    
    // Test vector 2: X25519 + BIKE Level 1
    let variant2 = HybridKemVariant {
        classical: ClassicalKemAlgorithm::X25519,
        post_quantum: PostQuantumKemAlgorithm::Bike(BikeVariant::Bike1Level1),
    };
    
    // Generate key pair
    let key_pair2 = HybridKemKeyPair::generate(variant2)?;
    
    // Get public key
    let public_key2 = key_pair2.public_key()?;
    
    // Encapsulate
    let (ciphertext2, shared_secret2) = public_key2.encapsulate()?;
    
    // Serialize the test vector
    result.extend_from_slice(b"TEST_VECTOR_2\n");
    result.extend_from_slice(b"Variant: X25519 + BIKE Level 1\n");
    
    let key_pair_bytes = key_pair2.to_bytes()?;
    result.extend_from_slice(b"KeyPair: ");
    for byte in &key_pair_bytes {
        result.extend_from_slice(format!("{:02x}", byte).as_bytes());
    }
    result.extend_from_slice(b"\n");
    
    let public_key_bytes = public_key2.to_bytes()?;
    result.extend_from_slice(b"PublicKey: ");
    for byte in &public_key_bytes {
        result.extend_from_slice(format!("{:02x}", byte).as_bytes());
    }
    result.extend_from_slice(b"\n");
    
    let ciphertext_bytes = ciphertext2.to_bytes()?;
    result.extend_from_slice(b"Ciphertext: ");
    for byte in &ciphertext_bytes {
        result.extend_from_slice(format!("{:02x}", byte).as_bytes());
    }
    result.extend_from_slice(b"\n");
    
    result.extend_from_slice(b"SharedSecret: ");
    for byte in &shared_secret2 {
        result.extend_from_slice(format!("{:02x}", byte).as_bytes());
    }
    result.extend_from_slice(b"\n");
    
    Ok(result)
} 