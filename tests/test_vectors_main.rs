// Main test file for running all test vectors
// This file serves as an entry point for running all test vectors

mod test_vectors;

use qasa::kyber::{KyberKeyPair, KyberPublicKey};
use qasa::dilithium::{DilithiumKeyPair, DilithiumPublicKey, CompressedSignature as DilithiumCompressedSignature};
use qasa::sphincsplus::{SphincsKeyPair, SphincsPublicKey, CompressedSignature as SphincsCompressedSignature};
use qasa::bike::{BikeKeyPair, BikePublicKey, CompressedCiphertext as BikeCompressedCiphertext};
use qasa::aes;
use qasa::secure_memory::LockedMemory;
use test_vectors::{kyber, dilithium, sphincsplus, bike, aes_gcm, secure_memory};
use std::fs;
use std::path::Path;
use std::io::Write;
use sha3::Digest;
use std::env;
use std::fs::File;

// Function to export test vectors to JSON files
fn export_test_vectors() -> std::io::Result<()> {
    // Create test_vectors directory if it doesn't exist
    let output_dir = Path::new("target/test_vectors");
    fs::create_dir_all(output_dir)?;
    
    // Export Kyber test vectors
    let kyber_vectors = kyber::standard_test_vectors();
    let kyber_json = serde_json::to_string_pretty(&kyber_vectors)
        .expect("Failed to serialize Kyber test vectors");
    fs::write(output_dir.join("kyber_standard.json"), kyber_json)?;
    
    let kyber_special_vectors = kyber::special_case_test_vectors();
    let kyber_special_json = serde_json::to_string_pretty(&kyber_special_vectors)
        .expect("Failed to serialize Kyber special case test vectors");
    fs::write(output_dir.join("kyber_special.json"), kyber_special_json)?;
    
    // Export Dilithium test vectors
    let dilithium_vectors = dilithium::standard_test_vectors();
    let dilithium_json = serde_json::to_string_pretty(&dilithium_vectors)
        .expect("Failed to serialize Dilithium test vectors");
    fs::write(output_dir.join("dilithium_standard.json"), dilithium_json)?;
    
    let dilithium_special_vectors = dilithium::special_case_test_vectors();
    let dilithium_special_json = serde_json::to_string_pretty(&dilithium_special_vectors)
        .expect("Failed to serialize Dilithium special case test vectors");
    fs::write(output_dir.join("dilithium_special.json"), dilithium_special_json)?;
    
    // Export SPHINCS+ test vectors
    let sphincsplus_vectors = sphincsplus::standard_test_vectors();
    let sphincsplus_json = serde_json::to_string_pretty(&sphincsplus_vectors)
        .expect("Failed to serialize SPHINCS+ test vectors");
    fs::write(output_dir.join("sphincsplus_standard.json"), sphincsplus_json)?;
    
    let sphincsplus_special_vectors = sphincsplus::special_case_test_vectors();
    let sphincsplus_special_json = serde_json::to_string_pretty(&sphincsplus_special_vectors)
        .expect("Failed to serialize SPHINCS+ special case test vectors");
    fs::write(output_dir.join("sphincsplus_special.json"), sphincsplus_special_json)?;
    
    // Export BIKE test vectors
    let bike_vectors = bike::standard_test_vectors();
    let bike_json = serde_json::to_string_pretty(&bike_vectors)
        .expect("Failed to serialize BIKE test vectors");
    fs::write(output_dir.join("bike_standard.json"), bike_json)?;
    
    let bike_special_vectors = bike::special_case_test_vectors();
    let bike_special_json = serde_json::to_string_pretty(&bike_special_vectors)
        .expect("Failed to serialize BIKE special case test vectors");
    fs::write(output_dir.join("bike_special.json"), bike_special_json)?;
    
    // Export AES-GCM test vectors
    let aes_gcm_vectors = aes_gcm::standard_test_vectors();
    let aes_gcm_json = serde_json::to_string_pretty(&aes_gcm_vectors)
        .expect("Failed to serialize AES-GCM test vectors");
    fs::write(output_dir.join("aes_gcm_standard.json"), aes_gcm_json)?;
    
    let aes_gcm_special_vectors = aes_gcm::special_case_test_vectors();
    let aes_gcm_special_json = serde_json::to_string_pretty(&aes_gcm_special_vectors)
        .expect("Failed to serialize AES-GCM special case test vectors");
    fs::write(output_dir.join("aes_gcm_special.json"), aes_gcm_special_json)?;
    
    // Export Secure Memory test vectors
    let secure_memory_vectors = secure_memory::standard_locked_memory_vectors();
    let secure_memory_json = serde_json::to_string_pretty(&secure_memory_vectors)
        .expect("Failed to serialize Secure Memory test vectors");
    fs::write(output_dir.join("secure_memory_standard.json"), secure_memory_json)?;
    
    let canary_buffer_vectors = secure_memory::standard_canary_buffer_vectors();
    let canary_buffer_json = serde_json::to_string_pretty(&canary_buffer_vectors)
        .expect("Failed to serialize Canary Buffer test vectors");
    fs::write(output_dir.join("canary_buffer_standard.json"), canary_buffer_json)?;
    
    // Create a README file with instructions
    let readme_content = r#"# QaSa Cryptography Module Test Vectors

This directory contains test vectors for the QaSa cryptography module, designed for interoperability testing with other implementations.

## Structure

- `kyber_standard.json`: Standard test vectors for Kyber KEM
- `kyber_special.json`: Special case test vectors for Kyber KEM
- `dilithium_standard.json`: Standard test vectors for Dilithium signatures
- `dilithium_special.json`: Special case test vectors for Dilithium signatures
- `sphincsplus_standard.json`: Standard test vectors for SPHINCS+ signatures
- `sphincsplus_special.json`: Special case test vectors for SPHINCS+ signatures
- `bike_standard.json`: Standard test vectors for BIKE
- `bike_special.json`: Special case test vectors for BIKE
- `aes_gcm_standard.json`: Standard test vectors for AES-GCM encryption
- `aes_gcm_special.json`: Special case test vectors for AES-GCM encryption
- `secure_memory_standard.json`: Test vectors for secure memory operations
- `canary_buffer_standard.json`: Test vectors for canary buffer operations

## Usage

These test vectors can be used to verify compatibility with other implementations of the same cryptographic algorithms. Each test vector includes all necessary inputs and expected outputs for the corresponding operation.

## Regenerating Test Vectors

To regenerate these test vectors, run:

```
cargo test --test test_vectors_main -- --nocapture
```

This will run all the test vector generation code and export the results to this directory.
"#;
    
    fs::write(output_dir.join("README.md"), readme_content)?;
    
    println!("Test vectors exported to {}", output_dir.display());
    
    Ok(())
}

#[test]
fn test_all_vectors() {
    // Test Kyber vectors
    let kyber_vectors = kyber::standard_test_vectors();
    for vector in kyber_vectors {
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
    let dilithium_vectors = dilithium::standard_test_vectors();
    for vector in dilithium_vectors {
        let pk = DilithiumPublicKey::from_bytes(&vector.public_key)
            .expect("Failed to deserialize Dilithium public key");
        
        let is_valid = pk.verify(&vector.message, &vector.signature)
            .expect("Failed to verify Dilithium signature");
        
        assert!(is_valid, "Dilithium signature verification failed");
    }
    
    // Test SPHINCS+ vectors
    let sphincsplus_vectors = sphincsplus::standard_test_vectors();
    for vector in sphincsplus_vectors {
        let pk = SphincsPublicKey::from_bytes(&vector.public_key)
            .expect("Failed to deserialize SPHINCS+ public key");
        
        let is_valid = pk.verify(&vector.message, &vector.signature)
            .expect("Failed to verify SPHINCS+ signature");
        
        assert!(is_valid, "SPHINCS+ signature verification failed");
    }
    
    // Test BIKE vectors
    let bike_vectors = bike::standard_test_vectors();
    for vector in bike_vectors {
        let keypair = BikeKeyPair::from_bytes(&vector.secret_key)
            .expect("Failed to deserialize BIKE keypair");
        
        let decapsulated = keypair.decapsulate(&vector.ciphertext)
            .expect("Failed to decapsulate BIKE ciphertext");
        
        assert_eq!(decapsulated, vector.shared_secret, 
                  "BIKE decapsulated shared secret doesn't match expected value");
    }
    
    // Test AES-GCM vectors
    let aes_gcm_vectors = aes_gcm::standard_test_vectors();
    for vector in aes_gcm_vectors {
        let decrypted = aes::decrypt(
            &vector.ciphertext,
            &vector.key,
            vector.aad.as_deref(),
        ).expect("Failed to decrypt AES-GCM ciphertext");
        
        assert_eq!(decrypted, vector.plaintext, 
                  "AES-GCM decrypted text doesn't match original plaintext");
    }
    
    // Test Secure Memory vectors
    let secure_memory_vectors = secure_memory::standard_locked_memory_vectors();
    for vector in secure_memory_vectors {
        let mut locked = LockedMemory::new(vector.data.len())
            .expect("Failed to create locked memory");
        
        locked.as_mut_slice().copy_from_slice(&vector.data);
        
        // Perform the same operations as in the vector generation
        for i in 0..vector.data.len() {
            if i % 2 == 0 {
                locked.as_mut_slice()[i] ^= 0x55;
            } else {
                locked.as_mut_slice()[i] ^= 0xAA;
            }
        }
        
        // Calculate hash of the modified data
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(locked.as_slice());
        let hash = hasher.finalize().to_vec();
        
        assert_eq!(hash, vector.expected_hash, "Secure memory hash mismatch");
    }
    
    // Export all test vectors to JSON files
    export_test_vectors().expect("Failed to export test vectors");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize QaSa
    qasa::init()?;
    
    // Get output file path from command line arguments or use default
    let args: Vec<String> = env::args().collect();
    let output_path = if args.len() > 1 {
        &args[1]
    } else {
        "test_vectors.txt"
    };
    
    println!("Generating test vectors...");
    
    // Generate all test vectors
    let test_vectors = test_vectors::generate_all_test_vectors()?;
    
    // Write test vectors to file
    let path = Path::new(output_path);
    let mut file = File::create(&path)?;
    file.write_all(&test_vectors)?;
    
    println!("Test vectors written to {}", output_path);
    
    Ok(())
} 