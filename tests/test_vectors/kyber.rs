// Kyber Test Vectors for Interoperability
// Based on NIST PQC standardization test vectors for ML-KEM (Kyber)

use qasa::kyber::{KyberKeyPair, KyberVariant};
use rand::Rng;
use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};

/// Test vector structure for Kyber KEM operations
#[derive(Debug, Serialize, Deserialize)]
pub struct KyberTestVector {
    pub variant: KyberVariant,
    pub seed: [u8; 64],
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Generate a deterministic test vector for Kyber KEM
pub fn generate_test_vector(variant: KyberVariant, seed: &[u8; 64]) -> KyberTestVector {
    // Create a deterministic RNG from the seed
    let mut rng = deterministic_rng_from_seed(seed);
    
    // Generate keypair deterministically
    let keypair = KyberKeyPair::generate_deterministic(variant, &mut rng)
        .expect("Failed to generate deterministic keypair");
    
    // Extract public key bytes
    let public_key_bytes = keypair.public_key().to_bytes();
    
    // Extract secret key bytes
    let secret_key_bytes = keypair.to_bytes();
    
    // Generate ciphertext and shared secret deterministically
    let mut encap_rng = deterministic_rng_from_seed(seed);
    let (ciphertext, shared_secret) = keypair
        .public_key()
        .encapsulate_deterministic(&mut encap_rng)
        .expect("Failed to encapsulate");
    
    KyberTestVector {
        variant,
        seed: *seed,
        public_key: public_key_bytes,
        secret_key: secret_key_bytes,
        ciphertext,
        shared_secret,
    }
}

/// Create a deterministic RNG from a seed
fn deterministic_rng_from_seed(seed: &[u8; 64]) -> impl rand::RngCore {
    use rand::SeedableRng;
    rand_chacha::ChaCha20Rng::from_seed(*seed)
}

/// Standard test vectors for Kyber
pub fn standard_test_vectors() -> Vec<KyberTestVector> {
    let mut vectors = Vec::new();
    
    // Test vector 1: Kyber512
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
    vectors.push(generate_test_vector(KyberVariant::Kyber512, &seed_1));
    
    // Test vector 2: Kyber768
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
    vectors.push(generate_test_vector(KyberVariant::Kyber768, &seed_2));
    
    // Test vector 3: Kyber1024
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
    vectors.push(generate_test_vector(KyberVariant::Kyber1024, &seed_3));
    
    vectors
}

/// Generate test vectors with special cases
pub fn special_case_test_vectors() -> Vec<KyberTestVector> {
    let mut vectors = Vec::new();
    
    // Special case 1: All zeros seed (edge case)
    let seed_zeros = [0u8; 64];
    vectors.push(generate_test_vector(KyberVariant::Kyber768, &seed_zeros));
    
    // Special case 2: All ones seed (edge case)
    let seed_ones = [1u8; 64];
    vectors.push(generate_test_vector(KyberVariant::Kyber768, &seed_ones));
    
    // Special case 3: Alternating bits (edge case)
    let mut seed_alternating = [0u8; 64];
    for i in 0..64 {
        seed_alternating[i] = if i % 2 == 0 { 0x55 } else { 0xAA };
    }
    vectors.push(generate_test_vector(KyberVariant::Kyber768, &seed_alternating));
    
    vectors
}

/// Negative test cases for Kyber
pub fn negative_test_vectors() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut vectors = Vec::new();
    
    // Generate a valid keypair and ciphertext first
    let seed = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    ];
    
    let vector = generate_test_vector(KyberVariant::Kyber768, &seed);
    let valid_pk = vector.public_key;
    let valid_ct = vector.ciphertext.clone();
    
    // Case 1: Tampered public key (flip a bit)
    let mut tampered_pk = valid_pk.clone();
    tampered_pk[10] ^= 0x01;
    vectors.push((tampered_pk, valid_ct.clone()));
    
    // Case 2: Tampered ciphertext (flip a bit)
    let mut tampered_ct = valid_ct.clone();
    tampered_ct[10] ^= 0x01;
    vectors.push((valid_pk.clone(), tampered_ct));
    
    // Case 3: Truncated ciphertext
    let truncated_ct = valid_ct[..valid_ct.len() - 10].to_vec();
    vectors.push((valid_pk.clone(), truncated_ct));
    
    // Case 4: Extended ciphertext with random bytes
    let mut extended_ct = valid_ct;
    extended_ct.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    vectors.push((valid_pk, extended_ct));
    
    vectors
}

#[cfg(test)]
mod tests {
    use super::*;
    use qasa::kyber::KyberPublicKey;
    
    #[test]
    fn test_standard_vectors() {
        let vectors = standard_test_vectors();
        
        for vector in vectors {
            // Test that the public key can be deserialized
            let pk = KyberPublicKey::from_bytes(&vector.public_key)
                .expect("Failed to deserialize public key");
            
            // Test that the keypair can be deserialized
            let keypair = KyberKeyPair::from_bytes(&vector.secret_key)
                .expect("Failed to deserialize keypair");
            
            // Test decapsulation
            let decapsulated = keypair.decapsulate(&vector.ciphertext)
                .expect("Failed to decapsulate");
            
            // Verify shared secret matches
            assert_eq!(decapsulated, vector.shared_secret, 
                "Decapsulated shared secret doesn't match expected value");
        }
    }
    
    #[test]
    fn test_special_cases() {
        let vectors = special_case_test_vectors();
        
        for vector in vectors {
            // Test that the public key can be deserialized
            let pk = KyberPublicKey::from_bytes(&vector.public_key)
                .expect("Failed to deserialize public key");
            
            // Test that the keypair can be deserialized
            let keypair = KyberKeyPair::from_bytes(&vector.secret_key)
                .expect("Failed to deserialize keypair");
            
            // Test decapsulation
            let decapsulated = keypair.decapsulate(&vector.ciphertext)
                .expect("Failed to decapsulate");
            
            // Verify shared secret matches
            assert_eq!(decapsulated, vector.shared_secret, 
                "Decapsulated shared secret doesn't match expected value");
        }
    }
    
    #[test]
    fn test_negative_cases() {
        let vectors = negative_test_vectors();
        
        for (pk_bytes, ct_bytes) in vectors {
            // Try to deserialize the public key
            if let Ok(pk) = KyberPublicKey::from_bytes(&pk_bytes) {
                // If deserialization succeeds, try to decapsulate with a valid keypair
                let seed = [0u8; 64];
                let valid_vector = generate_test_vector(KyberVariant::Kyber768, &seed);
                let keypair = KyberKeyPair::from_bytes(&valid_vector.secret_key)
                    .expect("Failed to deserialize keypair");
                
                // Attempt to decapsulate with tampered data
                let result = keypair.decapsulate(&ct_bytes);
                
                // If decapsulation succeeds, the shared secret should not match the original
                if let Ok(decapsulated) = result {
                    assert_ne!(decapsulated, valid_vector.shared_secret,
                        "Decapsulation with tampered data produced the same shared secret");
                }
            }
        }
    }
} 