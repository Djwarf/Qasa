// Test vectors module for interoperability testing
// This module contains comprehensive test vectors for all cryptographic algorithms
// implemented in the QaSa library, to ensure interoperability with other implementations

pub mod kyber;
pub mod dilithium;
pub mod sphincsplus;
pub mod bike;
pub mod hybrid;
pub mod aes_gcm;
pub mod secure_memory;

use qasa::error::CryptoResult;

/// Generate all test vectors
pub fn generate_all_test_vectors() -> CryptoResult<Vec<u8>> {
    let mut result = Vec::new();
    
    // Add header
    result.extend_from_slice(b"QaSa Cryptography Module Test Vectors\n");
    result.extend_from_slice(b"====================================\n\n");
    
    // Generate Kyber test vectors
    result.extend_from_slice(b"KYBER TEST VECTORS\n");
    result.extend_from_slice(b"=================\n\n");
    
    // Convert standard test vectors to text format
    let kyber_vectors = kyber::standard_test_vectors();
    for (i, vector) in kyber_vectors.iter().enumerate() {
        result.extend_from_slice(format!("Test Vector {}\n", i + 1).as_bytes());
        result.extend_from_slice(format!("Variant: {}\n", vector.variant).as_bytes());
        result.extend_from_slice(b"Public Key: ");
        for byte in &vector.public_key {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n");
        result.extend_from_slice(b"Ciphertext: ");
        for byte in &vector.ciphertext {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n");
        result.extend_from_slice(b"Shared Secret: ");
        for byte in &vector.shared_secret {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n\n");
    }
    
    // Generate Dilithium test vectors
    result.extend_from_slice(b"DILITHIUM TEST VECTORS\n");
    result.extend_from_slice(b"=====================\n\n");
    
    // Convert standard test vectors to text format
    let dilithium_vectors = dilithium::standard_test_vectors();
    for (i, vector) in dilithium_vectors.iter().enumerate() {
        result.extend_from_slice(format!("Test Vector {}\n", i + 1).as_bytes());
        result.extend_from_slice(format!("Variant: {}\n", vector.variant).as_bytes());
        result.extend_from_slice(b"Public Key: ");
        for byte in &vector.public_key {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n");
        result.extend_from_slice(b"Message: ");
        for byte in &vector.message {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n");
        result.extend_from_slice(b"Signature: ");
        for byte in &vector.signature {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n\n");
    }
    
    // Generate SPHINCS+ test vectors
    result.extend_from_slice(b"SPHINCS+ TEST VECTORS\n");
    result.extend_from_slice(b"====================\n\n");
    
    // Convert standard test vectors to text format
    let sphincs_vectors = sphincsplus::standard_test_vectors();
    for (i, vector) in sphincs_vectors.iter().enumerate() {
        result.extend_from_slice(format!("Test Vector {}\n", i + 1).as_bytes());
        result.extend_from_slice(format!("Variant: {}\n", vector.variant).as_bytes());
        result.extend_from_slice(b"Public Key: ");
        for byte in &vector.public_key {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n");
        result.extend_from_slice(b"Message: ");
        for byte in &vector.message {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n");
        result.extend_from_slice(b"Signature: ");
        for byte in &vector.signature {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n\n");
    }
    
    // Generate BIKE test vectors
    result.extend_from_slice(b"BIKE TEST VECTORS\n");
    result.extend_from_slice(b"===============\n\n");
    
    // Convert standard test vectors to text format
    let bike_vectors = bike::standard_test_vectors();
    for (i, vector) in bike_vectors.iter().enumerate() {
        result.extend_from_slice(format!("Test Vector {}\n", i + 1).as_bytes());
        result.extend_from_slice(format!("Variant: {}\n", vector.variant).as_bytes());
        result.extend_from_slice(b"Public Key: ");
        for byte in &vector.public_key {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n");
        result.extend_from_slice(b"Ciphertext: ");
        for byte in &vector.ciphertext {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n");
        result.extend_from_slice(b"Shared Secret: ");
        for byte in &vector.shared_secret {
            result.extend_from_slice(format!("{:02x}", byte).as_bytes());
        }
        result.extend_from_slice(b"\n\n");
    }
    
    // Generate hybrid test vectors
    result.extend_from_slice(b"HYBRID TEST VECTORS\n");
    result.extend_from_slice(b"=================\n\n");
    result.extend_from_slice(&hybrid::generate_hybrid_kem_test_vectors()?);
    
    Ok(result)
}