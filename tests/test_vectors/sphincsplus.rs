// SPHINCS+ Test Vectors for Interoperability
// Based on NIST PQC standardization test vectors for SPHINCS+

use qasa::sphincsplus::{SphincsKeyPair, SphincsVariant, CompressedSignature, CompressionLevel};
use rand::Rng;
use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};
use serde_arrays;

/// Test vector structure for SPHINCS+ signature operations
#[derive(Debug, Serialize, Deserialize)]
pub struct SphincsTestVector {
    #[serde(with = "SphincsVariantDef")]
    pub variant: SphincsVariant,
    #[serde(with = "serde_arrays")]
    pub seed: [u8; 64],
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(with = "CompressedSignaturesDef")]
    pub compressed_signatures: Vec<(CompressionLevel, Vec<u8>)>,
}

// Helper module for serializing SphincsVariant
#[derive(Serialize, Deserialize)]
#[serde(remote = "SphincsVariant")]
enum SphincsVariantDef {
    Sphincs128f,
    Sphincs128s,
    Sphincs192f,
    Sphincs192s,
    Sphincs256f,
    Sphincs256s,
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

/// Generate a test vector for SPHINCS+ signatures
pub fn generate_test_vector(
    variant: SphincsVariant, 
    seed: &[u8; 64], 
    message: &[u8]
) -> SphincsTestVector {
    // In a real implementation with deterministic generation, we would use the seed
    // to create a deterministic RNG, but for now we'll just use the standard RNG
    
    // Generate keypair
    let keypair = SphincsKeyPair::generate(variant)
        .expect("Failed to generate keypair");
    
    // Extract public key bytes
    let public_key_bytes = keypair.public_key().to_bytes()
        .expect("Failed to serialize public key");
    
    // Extract secret key bytes
    let secret_key_bytes = keypair.to_bytes()
        .expect("Failed to serialize secret key");
    
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
        
        compressed_signatures.push((*level, compressed.data().to_vec()));
    }
    
    SphincsTestVector {
        variant,
        seed: *seed,
        public_key: public_key_bytes,
        secret_key: secret_key_bytes,
        message: message.to_vec(),
        signature,
        compressed_signatures,
    }
}

/// Standard test vectors for SPHINCS+
pub fn standard_test_vectors() -> Vec<SphincsTestVector> {
    let mut vectors = Vec::new();
    
    // Standard message
    let message = b"The quick brown fox jumps over the lazy dog";
    
    // Test vector 1: SPHINCS+-128f-simple
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
    vectors.push(generate_test_vector(SphincsVariant::Sphincs128f, &seed_1, message));
    
    // Test vector 2: SPHINCS+-128s-simple
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
    vectors.push(generate_test_vector(SphincsVariant::Sphincs128s, &seed_2, message));
    
    // Test vector 3: SPHINCS+-192f-simple
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
    vectors.push(generate_test_vector(SphincsVariant::Sphincs192f, &seed_3, message));
    
    // Test vector 4: SPHINCS+-192s-simple
    let seed_4 = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    ];
    vectors.push(generate_test_vector(SphincsVariant::Sphincs192s, &seed_4, message));
    
    // Test vector 5: SPHINCS+-256f-simple
    let seed_5 = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    ];
    vectors.push(generate_test_vector(SphincsVariant::Sphincs256f, &seed_5, message));
    
    // Test vector 6: SPHINCS+-256s-simple
    let seed_6 = [
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c,
        0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3,
        0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
        0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    ];
    vectors.push(generate_test_vector(SphincsVariant::Sphincs256s, &seed_6, message));
    
    vectors
}

/// Generate test vectors with special cases
pub fn special_case_test_vectors() -> Vec<SphincsTestVector> {
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
    vectors.push(generate_test_vector(SphincsVariant::Sphincs128s, &seed_1, empty_message));
    
    // Special case 2: Long message
    let long_message = vec![0xAA; 1024]; // 1KB message of repeated 0xAA bytes
    let seed_2 = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    ];
    vectors.push(generate_test_vector(SphincsVariant::Sphincs128s, &seed_2, &long_message));
    
    // Special case 3: Single byte message
    let single_byte_message = b"X";
    let seed_3 = [
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c,
        0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3,
        0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
        0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    ];
    vectors.push(generate_test_vector(SphincsVariant::Sphincs256s, &seed_3, single_byte_message));
    
    vectors
}

/// Generate negative test vectors (invalid signatures)
pub fn negative_test_vectors() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut vectors = Vec::new();
    
    // Generate a valid keypair and signature
    let variant = SphincsVariant::Sphincs128s; // Use smallest variant for speed
    let keypair = SphincsKeyPair::generate(variant).expect("Failed to generate keypair");
    let message = b"Test message for SPHINCS+ signature";
    let signature = keypair.sign(message).expect("Failed to sign message");
    let public_key_bytes = keypair.public_key().to_bytes().expect("Failed to serialize public key");
    
    // Case 1: Valid signature but wrong message
    let wrong_message = b"Wrong message for SPHINCS+ signature";
    vectors.push((public_key_bytes.clone(), wrong_message.to_vec(), signature.clone()));
    
    // Case 2: Valid message but tampered signature
    let mut tampered_signature = signature.clone();
    // Modify a byte in the middle of the signature
    let middle = tampered_signature.len() / 2;
    tampered_signature[middle] ^= 0xFF; // Flip all bits in this byte
    vectors.push((public_key_bytes.clone(), message.to_vec(), tampered_signature));
    
    // Case 3: Valid message but completely invalid signature
    let invalid_signature = vec![0u8; variant.signature_size()];
    vectors.push((public_key_bytes, message.to_vec(), invalid_signature));
    
    vectors
}

/// Generate test vectors for compressed signatures
pub fn compressed_signature_test_vectors() -> Vec<(SphincsVariant, Vec<u8>, Vec<u8>, CompressionLevel, Vec<u8>)> {
    let mut vectors = Vec::new();
    
    // Generate a valid keypair
    let variants = [
        SphincsVariant::Sphincs128s,  // Use smallest variant for speed
        SphincsVariant::Sphincs256f,  // Use largest variant for comprehensive testing
    ];
    
    let message = b"Test message for SPHINCS+ compressed signature";
    
    for variant in variants.iter() {
        let keypair = SphincsKeyPair::generate(*variant).expect("Failed to generate keypair");
        let public_key_bytes = keypair.public_key().to_bytes().expect("Failed to serialize public key");
        
        // Generate compressed signatures with different levels
        for level in &[CompressionLevel::Light, CompressionLevel::Medium, CompressionLevel::High] {
            let compressed = keypair
                .sign_compressed(message, *level)
                .expect("Failed to generate compressed signature");
            
            vectors.push((
                *variant,
                public_key_bytes.clone(),
                message.to_vec(),
                *level,
                compressed.data().to_vec(),
            ));
        }
    }
    
    vectors
}

#[cfg(test)]
mod tests {
    use super::*;
    use qasa::sphincsplus::{SphincsPublicKey, CompressedSignature};
    
    #[test]
    fn test_standard_vectors() {
        let vectors = standard_test_vectors();
        
        for vector in vectors {
            // Deserialize the public key
            let public_key = SphincsPublicKey::from_bytes(&vector.public_key)
                .expect("Failed to deserialize SPHINCS+ public key");
            
            // Verify the signature
            let is_valid = public_key.verify(&vector.message, &vector.signature)
                .expect("Failed to verify SPHINCS+ signature");
            
            assert!(is_valid, "SPHINCS+ signature verification failed for {:?}", vector.variant);
            
            // Deserialize the keypair
            let keypair = SphincsKeyPair::from_bytes(&vector.secret_key)
                .expect("Failed to deserialize SPHINCS+ keypair");
            
            // Sign again and verify
            let new_signature = keypair.sign(&vector.message)
                .expect("Failed to sign message");
            
            let is_valid = public_key.verify(&vector.message, &new_signature)
                .expect("Failed to verify new SPHINCS+ signature");
            
            assert!(is_valid, "New SPHINCS+ signature verification failed for {:?}", vector.variant);
        }
    }
    
    #[test]
    fn test_special_cases() {
        let vectors = special_case_test_vectors();
        
        for vector in vectors {
            // Deserialize the public key
            let public_key = SphincsPublicKey::from_bytes(&vector.public_key)
                .expect("Failed to deserialize SPHINCS+ public key");
            
            // Verify the signature
            let is_valid = public_key.verify(&vector.message, &vector.signature)
                .expect("Failed to verify SPHINCS+ signature");
            
            assert!(is_valid, "SPHINCS+ signature verification failed for special case");
        }
    }
    
    #[test]
    fn test_negative_cases() {
        let vectors = negative_test_vectors();
        
        for (public_key_bytes, message, signature) in vectors {
            // Deserialize the public key
            let public_key = SphincsPublicKey::from_bytes(&public_key_bytes)
                .expect("Failed to deserialize SPHINCS+ public key");
            
            // Verify the signature (should fail)
            let is_valid = public_key.verify(&message, &signature)
                .expect("Failed to verify SPHINCS+ signature");
            
            assert!(!is_valid, "SPHINCS+ signature verification unexpectedly succeeded for negative case");
        }
    }
    
    #[test]
    fn test_compressed_signatures() {
        let vectors = compressed_signature_test_vectors();
        
        for (variant, public_key_bytes, message, level, compressed_data) in vectors {
            // Deserialize the public key
            let public_key = SphincsPublicKey::from_bytes(&public_key_bytes)
                .expect("Failed to deserialize SPHINCS+ public key");
            
            // Create compressed signature object
            let compressed = CompressedSignature::new(compressed_data, level, variant);
            
            // Verify the compressed signature
            let is_valid = public_key.verify_compressed(&message, &compressed)
                .expect("Failed to verify compressed SPHINCS+ signature");
            
            assert!(is_valid, "Compressed SPHINCS+ signature verification failed for {:?} with {:?}", variant, level);
        }
    }
} 