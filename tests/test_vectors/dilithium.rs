// Dilithium Test Vectors for Interoperability
// Based on NIST PQC standardization test vectors for ML-DSA (Dilithium)

use qasa::dilithium::{DilithiumKeyPair, DilithiumVariant, CompressedSignature, CompressionLevel};
use rand::Rng;
use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};
use serde_arrays;

/// Test vector structure for Dilithium signature operations
#[derive(Debug, Serialize, Deserialize)]
pub struct DilithiumTestVector {
    #[serde(with = "DilithiumVariantDef")]
    pub variant: DilithiumVariant,
    #[serde(with = "serde_arrays")]
    pub seed: [u8; 64],
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(with = "CompressedSignaturesDef")]
    pub compressed_signatures: Vec<(CompressionLevel, Vec<u8>)>,
}

// Helper module for serializing DilithiumVariant
#[derive(Serialize, Deserialize)]
#[serde(remote = "DilithiumVariant")]
enum DilithiumVariantDef {
    Dilithium2,
    Dilithium3,
    Dilithium5,
}

// Helper module for serializing CompressionLevel
#[derive(Serialize, Deserialize)]
#[serde(remote = "CompressionLevel")]
enum CompressionLevelDef {
    None,
    Light,
    Medium,
    High,
}

// Helper module for serializing Vec<(CompressionLevel, Vec<u8>)>
mod CompressedSignaturesDef {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct CompressedSignatureEntry {
        #[serde(with = "CompressionLevelDef")]
        level: CompressionLevel,
        data: Vec<u8>,
    }

    pub fn serialize<S>(
        compressed_signatures: &Vec<(CompressionLevel, Vec<u8>)>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entries: Vec<CompressedSignatureEntry> = compressed_signatures
            .iter()
            .map(|(level, data)| CompressedSignatureEntry {
                level: *level,
                data: data.clone(),
            })
            .collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Vec<(CompressionLevel, Vec<u8>)>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<CompressedSignatureEntry>::deserialize(deserializer)?;
        Ok(entries
            .into_iter()
            .map(|entry| (entry.level, entry.data))
            .collect())
    }
}

/// Generate a test vector for Dilithium signatures
pub fn generate_test_vector(
    variant: DilithiumVariant, 
    seed: &[u8; 64], 
    message: &[u8]
) -> DilithiumTestVector {
    // In a real implementation with deterministic generation, we would use the seed
    // to create a deterministic RNG, but for now we'll just use the standard RNG
    
    // Generate keypair
    let keypair = DilithiumKeyPair::generate(variant)
        .expect("Failed to generate keypair");
    
    // Extract public key bytes
    let public_key_bytes = keypair.public_key().to_bytes();
    
    // Extract secret key bytes
    let secret_key_bytes = keypair.to_bytes();
    
    // Sign the message
    let signature = keypair
        .sign(message)
        .expect("Failed to sign message");
    
    // Generate compressed signatures at different levels
    let mut compressed_signatures = Vec::new();
    for level in &[CompressionLevel::Light, CompressionLevel::Medium, CompressionLevel::High] {
        let compressed = keypair
            .sign_compressed(message, *level)
            .expect("Failed to generate compressed signature");
        
        compressed_signatures.push((*level, compressed.to_bytes()));
    }
    
    DilithiumTestVector {
        variant,
        seed: *seed,
        public_key: public_key_bytes,
        secret_key: secret_key_bytes,
        message: message.to_vec(),
        signature,
        compressed_signatures,
    }
}

/// Create a deterministic RNG from a seed (not used in this implementation)
fn deterministic_rng_from_seed(seed: &[u8; 64]) -> impl rand::RngCore {
    use rand::SeedableRng;
    rand_chacha::ChaCha20Rng::from_seed(*seed)
}

/// Standard test vectors for Dilithium
pub fn standard_test_vectors() -> Vec<DilithiumTestVector> {
    let mut vectors = Vec::new();
    
    // Standard message
    let message = b"The quick brown fox jumps over the lazy dog";
    
    // Test vector 1: Dilithium2
    let seed_1 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ];
    vectors.push(generate_test_vector(DilithiumVariant::Dilithium2, &seed_1, message));
    
    // Test vector 2: Dilithium3
    let seed_2 = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    ];
    vectors.push(generate_test_vector(DilithiumVariant::Dilithium3, &seed_2, message));
    
    // Test vector 3: Dilithium5
    let seed_3 = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    ];
    vectors.push(generate_test_vector(DilithiumVariant::Dilithium5, &seed_3, message));
    
    vectors
}

/// Generate test vectors with special cases
pub fn special_case_test_vectors() -> Vec<DilithiumTestVector> {
    let mut vectors = Vec::new();
    
    // Special case 1: Empty message
    let empty_message = b"";
    let seed_1 = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    ];
    vectors.push(generate_test_vector(DilithiumVariant::Dilithium3, &seed_1, empty_message));
    
    // Special case 2: Very large message (triggers multiple blocks in hash)
    let large_message = vec![0xAA; 1024]; // 1KB of 0xAA bytes
    let seed_2 = [0x42u8; 64];
    vectors.push(generate_test_vector(DilithiumVariant::Dilithium3, &seed_2, &large_message));
    
    // Special case 3: Message with all zeros
    let zero_message = vec![0u8; 100]; // 100 zero bytes
    let seed_3 = [0x69u8; 64];
    vectors.push(generate_test_vector(DilithiumVariant::Dilithium3, &seed_3, &zero_message));
    
    vectors
}

/// Negative test cases for Dilithium
pub fn negative_test_vectors() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut vectors = Vec::new();
    
    // Generate a valid keypair, message, and signature first
    let seed = [0xAAu8; 64];
    let message = b"This is a test message for negative test cases";
    let vector = generate_test_vector(DilithiumVariant::Dilithium3, &seed, message);
    
    let valid_pk = vector.public_key;
    let valid_message = vector.message.clone();
    let valid_sig = vector.signature.clone();
    
    // Case 1: Tampered public key (flip a bit)
    let mut tampered_pk = valid_pk.clone();
    tampered_pk[10] ^= 0x01;
    vectors.push((tampered_pk, valid_message.clone(), valid_sig.clone()));
    
    // Case 2: Tampered message (change a character)
    let mut tampered_message = valid_message.clone();
    if !tampered_message.is_empty() {
        tampered_message[tampered_message.len() / 2] ^= 0x01;
    }
    vectors.push((valid_pk.clone(), tampered_message, valid_sig.clone()));
    
    // Case 3: Tampered signature (flip a bit)
    let mut tampered_sig = valid_sig.clone();
    tampered_sig[10] ^= 0x01;
    vectors.push((valid_pk.clone(), valid_message.clone(), tampered_sig));
    
    // Case 4: Truncated signature
    let truncated_sig = valid_sig[..valid_sig.len() - 10].to_vec();
    vectors.push((valid_pk.clone(), valid_message.clone(), truncated_sig));
    
    // Case 5: Extended signature with random bytes
    let mut extended_sig = valid_sig;
    extended_sig.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    vectors.push((valid_pk, valid_message, extended_sig));
    
    vectors
}

/// Test vectors specifically for compressed signatures
pub fn compressed_signature_test_vectors() -> Vec<(DilithiumVariant, Vec<u8>, Vec<u8>, CompressionLevel, Vec<u8>)> {
    let mut vectors = Vec::new();
    
    // Generate test vectors for each compression level
    for variant in &[DilithiumVariant::Dilithium2, DilithiumVariant::Dilithium3, DilithiumVariant::Dilithium5] {
        for level in &[CompressionLevel::Light, CompressionLevel::Medium, CompressionLevel::High] {
            let seed = [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            ];
            let message = format!("Test message for {} with compression level {:?}", 
                                 variant, level).into_bytes();
            
            // Create a deterministic RNG
            let mut rng = deterministic_rng_from_seed(&seed);
            
            // Generate keypair
            let keypair = DilithiumKeyPair::generate_deterministic(*variant, &mut rng)
                .expect("Failed to generate keypair");
            
            // Get public key
            let pk_bytes = keypair.public_key().to_bytes();
            
            // Generate compressed signature
            let mut sign_rng = deterministic_rng_from_seed(&seed);
            let compressed_sig = keypair
                .sign_compressed_deterministic(&message, *level, &mut sign_rng)
                .expect("Failed to create compressed signature");
            
            // Add to vectors
            vectors.push((*variant, pk_bytes, message, *level, compressed_sig.to_bytes()));
        }
    }
    
    vectors
}

#[cfg(test)]
mod tests {
    use super::*;
    use qasa::dilithium::{DilithiumPublicKey, CompressedSignature};
    
    #[test]
    fn test_standard_vectors() {
        let vectors = standard_test_vectors();
        
        for vector in vectors {
            // Test that the public key can be deserialized
            let pk = DilithiumPublicKey::from_bytes(&vector.public_key)
                .expect("Failed to deserialize public key");
            
            // Test that the keypair can be deserialized
            let keypair = DilithiumKeyPair::from_bytes(&vector.secret_key)
                .expect("Failed to deserialize keypair");
            
            // Test signature verification
            let is_valid = pk.verify(&vector.message, &vector.signature)
                .expect("Failed to verify signature");
            
            // Verify signature is valid
            assert!(is_valid, "Signature verification failed");
            
            // Test compressed signatures
            for (level, compressed_bytes) in &vector.compressed_signatures {
                let compressed = CompressedSignature::from_bytes(compressed_bytes)
                    .expect("Failed to deserialize compressed signature");
                
                let is_valid = pk.verify_compressed(&vector.message, &compressed)
                    .expect("Failed to verify compressed signature");
                
                assert!(is_valid, "Compressed signature verification failed for level {:?}", level);
            }
        }
    }
    
    #[test]
    fn test_special_cases() {
        let vectors = special_case_test_vectors();
        
        for vector in vectors {
            // Test that the public key can be deserialized
            let pk = DilithiumPublicKey::from_bytes(&vector.public_key)
                .expect("Failed to deserialize public key");
            
            // Test signature verification
            let is_valid = pk.verify(&vector.message, &vector.signature)
                .expect("Failed to verify signature");
            
            // Verify signature is valid
            assert!(is_valid, "Signature verification failed for special case");
            
            // Test compressed signatures
            for (level, compressed_bytes) in &vector.compressed_signatures {
                let compressed = CompressedSignature::from_bytes(compressed_bytes)
                    .expect("Failed to deserialize compressed signature");
                
                let is_valid = pk.verify_compressed(&vector.message, &compressed)
                    .expect("Failed to verify compressed signature");
                
                assert!(is_valid, "Compressed signature verification failed for level {:?}", level);
            }
        }
    }
    
    #[test]
    fn test_negative_cases() {
        let vectors = negative_test_vectors();
        
        for (pk_bytes, message, sig_bytes) in vectors {
            // Try to deserialize the public key
            if let Ok(pk) = DilithiumPublicKey::from_bytes(&pk_bytes) {
                // Attempt to verify with tampered data
                let result = pk.verify(&message, &sig_bytes);
                
                // Verification should either fail or return false
                match result {
                    Ok(is_valid) => assert!(!is_valid, "Signature verification should fail with tampered data"),
                    Err(_) => {} // Error is expected for some cases
                }
            }
        }
    }
    
    #[test]
    fn test_compressed_signatures() {
        let vectors = compressed_signature_test_vectors();
        
        for (variant, pk_bytes, message, level, compressed_bytes) in vectors {
            // Deserialize public key
            let pk = DilithiumPublicKey::from_bytes(&pk_bytes)
                .expect("Failed to deserialize public key");
            
            // Deserialize compressed signature
            let compressed = CompressedSignature::from_bytes(&compressed_bytes)
                .expect("Failed to deserialize compressed signature");
            
            // Verify the compressed signature
            let is_valid = pk.verify_compressed(&message, &compressed)
                .expect("Failed to verify compressed signature");
            
            assert!(is_valid, "Compressed signature verification failed for variant {:?} with level {:?}", 
                   variant, level);
            
            // Check that the compression level matches
            assert_eq!(compressed.compression_level(), level, 
                      "Compression level mismatch for variant {:?}", variant);
        }
    }
} 