// Simple test vectors for interoperability testing
// This file contains test vectors for the QaSa cryptography module

use qasa::kyber::{KyberKeyPair, KyberVariant};
use qasa::dilithium::{DilithiumKeyPair, DilithiumPublicKey, DilithiumVariant};
use qasa::aes;
use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};

// Kyber test vector structure
#[derive(Debug, Serialize, Deserialize)]
struct KyberTestVector {
    variant: String,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

// Dilithium test vector structure
#[derive(Debug, Serialize, Deserialize)]
struct DilithiumTestVector {
    variant: String,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

// AES-GCM test vector structure
#[derive(Debug, Serialize, Deserialize)]
struct AesGcmTestVector {
    key: Vec<u8>,
    plaintext: Vec<u8>,
    aad: Option<Vec<u8>>,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

// Function to export test vectors to JSON files
fn export_test_vectors() -> std::io::Result<()> {
    // Create test_vectors directory if it doesn't exist
    let output_dir = Path::new("target/test_vectors");
    fs::create_dir_all(output_dir)?;
    
    // Generate and export Kyber test vectors
    let kyber_vectors = generate_kyber_test_vectors();
    let kyber_json = serde_json::to_string_pretty(&kyber_vectors)
        .expect("Failed to serialize Kyber test vectors");
    fs::write(output_dir.join("kyber.json"), kyber_json)?;
    
    // Generate and export Dilithium test vectors
    let dilithium_vectors = generate_dilithium_test_vectors();
    let dilithium_json = serde_json::to_string_pretty(&dilithium_vectors)
        .expect("Failed to serialize Dilithium test vectors");
    fs::write(output_dir.join("dilithium.json"), dilithium_json)?;
    
    // Generate and export AES-GCM test vectors
    let aes_gcm_vectors = generate_aes_gcm_test_vectors();
    let aes_gcm_json = serde_json::to_string_pretty(&aes_gcm_vectors)
        .expect("Failed to serialize AES-GCM test vectors");
    fs::write(output_dir.join("aes_gcm.json"), aes_gcm_json)?;
    
    // Create a README file with instructions
    let readme_content = r#"# QaSa Cryptography Module Test Vectors

This directory contains test vectors for the QaSa cryptography module, designed for interoperability testing with other implementations.

## Structure

- `kyber.json`: Test vectors for Kyber KEM
- `dilithium.json`: Test vectors for Dilithium signatures
- `aes_gcm.json`: Test vectors for AES-GCM encryption

## Usage

These test vectors can be used to verify compatibility with other implementations of the same cryptographic algorithms. Each test vector includes all necessary inputs and expected outputs for the corresponding operation.

## Regenerating Test Vectors

To regenerate these test vectors, run:

```
cargo test --test test_vectors_simple -- --nocapture
```

This will run all the test vector generation code and export the results to this directory.
"#;
    
    fs::write(output_dir.join("README.md"), readme_content)?;
    
    println!("Test vectors exported to {}", output_dir.display());
    
    Ok(())
}

// Generate Kyber test vectors
fn generate_kyber_test_vectors() -> Vec<KyberTestVector> {
    let mut vectors = Vec::new();
    
    // Test vector for Kyber512
    let keypair_512 = KyberKeyPair::generate(KyberVariant::Kyber512)
        .expect("Failed to generate Kyber512 keypair");
    
    let public_key_512 = keypair_512.public_key().to_bytes()
        .expect("Failed to serialize Kyber512 public key");
    
    let secret_key_512 = keypair_512.to_bytes()
        .expect("Failed to serialize Kyber512 secret key");
    
    let (ciphertext_512, shared_secret_512) = keypair_512.public_key().encapsulate()
        .expect("Failed to encapsulate with Kyber512");
    
    vectors.push(KyberTestVector {
        variant: "Kyber512".to_string(),
        public_key: public_key_512,
        secret_key: secret_key_512,
        ciphertext: ciphertext_512,
        shared_secret: shared_secret_512,
    });
    
    // Test vector for Kyber768
    let keypair_768 = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Kyber768 keypair");
    
    let public_key_768 = keypair_768.public_key().to_bytes()
        .expect("Failed to serialize Kyber768 public key");
    
    let secret_key_768 = keypair_768.to_bytes()
        .expect("Failed to serialize Kyber768 secret key");
    
    let (ciphertext_768, shared_secret_768) = keypair_768.public_key().encapsulate()
        .expect("Failed to encapsulate with Kyber768");
    
    vectors.push(KyberTestVector {
        variant: "Kyber768".to_string(),
        public_key: public_key_768,
        secret_key: secret_key_768,
        ciphertext: ciphertext_768,
        shared_secret: shared_secret_768,
    });
    
    // Test vector for Kyber1024
    let keypair_1024 = KyberKeyPair::generate(KyberVariant::Kyber1024)
        .expect("Failed to generate Kyber1024 keypair");
    
    let public_key_1024 = keypair_1024.public_key().to_bytes()
        .expect("Failed to serialize Kyber1024 public key");
    
    let secret_key_1024 = keypair_1024.to_bytes()
        .expect("Failed to serialize Kyber1024 secret key");
    
    let (ciphertext_1024, shared_secret_1024) = keypair_1024.public_key().encapsulate()
        .expect("Failed to encapsulate with Kyber1024");
    
    vectors.push(KyberTestVector {
        variant: "Kyber1024".to_string(),
        public_key: public_key_1024,
        secret_key: secret_key_1024,
        ciphertext: ciphertext_1024,
        shared_secret: shared_secret_1024,
    });
    
    vectors
}

// Generate Dilithium test vectors
fn generate_dilithium_test_vectors() -> Vec<DilithiumTestVector> {
    let mut vectors = Vec::new();
    let message = b"The quick brown fox jumps over the lazy dog";
    
    // Test vector for Dilithium2
    let keypair_2 = DilithiumKeyPair::generate(DilithiumVariant::Dilithium2)
        .expect("Failed to generate Dilithium2 keypair");
    
    let public_key_2 = keypair_2.public_key().to_bytes()
        .expect("Failed to serialize Dilithium2 public key");
    
    let secret_key_2 = keypair_2.to_bytes()
        .expect("Failed to serialize Dilithium2 secret key");
    
    let signature_2 = keypair_2.sign(message)
        .expect("Failed to sign with Dilithium2");
    
    vectors.push(DilithiumTestVector {
        variant: "Dilithium2".to_string(),
        public_key: public_key_2,
        secret_key: secret_key_2,
        message: message.to_vec(),
        signature: signature_2,
    });
    
    // Test vector for Dilithium3
    let keypair_3 = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Dilithium3 keypair");
    
    let public_key_3 = keypair_3.public_key().to_bytes()
        .expect("Failed to serialize Dilithium3 public key");
    
    let secret_key_3 = keypair_3.to_bytes()
        .expect("Failed to serialize Dilithium3 secret key");
    
    let signature_3 = keypair_3.sign(message)
        .expect("Failed to sign with Dilithium3");
    
    vectors.push(DilithiumTestVector {
        variant: "Dilithium3".to_string(),
        public_key: public_key_3,
        secret_key: secret_key_3,
        message: message.to_vec(),
        signature: signature_3,
    });
    
    // Test vector for Dilithium5
    let keypair_5 = DilithiumKeyPair::generate(DilithiumVariant::Dilithium5)
        .expect("Failed to generate Dilithium5 keypair");
    
    let public_key_5 = keypair_5.public_key().to_bytes()
        .expect("Failed to serialize Dilithium5 public key");
    
    let secret_key_5 = keypair_5.to_bytes()
        .expect("Failed to serialize Dilithium5 secret key");
    
    let signature_5 = keypair_5.sign(message)
        .expect("Failed to sign with Dilithium5");
    
    vectors.push(DilithiumTestVector {
        variant: "Dilithium5".to_string(),
        public_key: public_key_5,
        secret_key: secret_key_5,
        message: message.to_vec(),
        signature: signature_5,
    });
    
    vectors
}

// Generate AES-GCM test vectors
fn generate_aes_gcm_test_vectors() -> Vec<AesGcmTestVector> {
    let mut vectors = Vec::new();
    
    // Test vector 1: Basic encryption with 32-byte key
    let key_1 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let plaintext_1 = b"Hello, world!";
    
    let (ciphertext_1, nonce_1) = aes::encrypt(plaintext_1, &key_1, None)
        .expect("Failed to encrypt plaintext 1");
    
    vectors.push(AesGcmTestVector {
        key: key_1.to_vec(),
        plaintext: plaintext_1.to_vec(),
        aad: None,
        ciphertext: ciphertext_1,
        nonce: nonce_1,
    });
    
    // Test vector 2: Encryption with AAD
    let key_2 = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ];
    let plaintext_2 = b"Secret message with AAD";
    let aad_2 = b"Additional authenticated data";
    
    let (ciphertext_2, nonce_2) = aes::encrypt(plaintext_2, &key_2, Some(aad_2))
        .expect("Failed to encrypt plaintext 2");
    
    vectors.push(AesGcmTestVector {
        key: key_2.to_vec(),
        plaintext: plaintext_2.to_vec(),
        aad: Some(aad_2.to_vec()),
        ciphertext: ciphertext_2,
        nonce: nonce_2,
    });
    
    // Test vector 3: 32-byte key (AES-256)
    let key_3 = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    ];
    let plaintext_3 = b"AES-256 test vector with AAD";
    let aad_3 = b"AES-256 additional authenticated data";
    
    let (ciphertext_3, nonce_3) = aes::encrypt(plaintext_3, &key_3, Some(aad_3))
        .expect("Failed to encrypt plaintext 3");
    
    vectors.push(AesGcmTestVector {
        key: key_3.to_vec(),
        plaintext: plaintext_3.to_vec(),
        aad: Some(aad_3.to_vec()),
        ciphertext: ciphertext_3,
        nonce: nonce_3,
    });
    
    vectors
}

// Test function to verify test vectors
#[test]
fn test_all_vectors() {
    // Test Kyber vectors
    let kyber_vectors = generate_kyber_test_vectors();
    for vector in &kyber_vectors {
        // Test that the keypair can be deserialized
        let keypair = KyberKeyPair::from_bytes(&vector.secret_key)
            .expect("Failed to deserialize Kyber keypair");
        
        // Test decapsulation
        let decapsulated = keypair.decapsulate(&vector.ciphertext)
            .expect("Failed to decapsulate");
        
        assert_eq!(decapsulated, vector.shared_secret, 
                  "Kyber decapsulated shared secret doesn't match expected value");
    }
    
    // Test Dilithium vectors
    let dilithium_vectors = generate_dilithium_test_vectors();
    for vector in &dilithium_vectors {
        let pk = DilithiumPublicKey::from_bytes(&vector.public_key)
            .expect("Failed to deserialize Dilithium public key");
        
        let is_valid = pk.verify(&vector.message, &vector.signature)
            .expect("Failed to verify Dilithium signature");
        
        assert!(is_valid, "Dilithium signature verification failed");
    }
    
    // Test AES-GCM vectors
    let aes_gcm_vectors = generate_aes_gcm_test_vectors();
    for vector in &aes_gcm_vectors {
        let decrypted = aes::decrypt(
            &vector.ciphertext,
            &vector.key,
            &vector.nonce,
            vector.aad.as_deref()
        ).expect("Failed to decrypt AES-GCM ciphertext");
        
        assert_eq!(decrypted, vector.plaintext, 
                  "AES-GCM decrypted text doesn't match original plaintext");
    }
    
    // Export all test vectors to JSON files
    export_test_vectors().expect("Failed to export test vectors");
} 