// BIKE Test Vectors for Interoperability
// Based on NIST PQC standardization test vectors for BIKE

use qasa::bike::{BikeKeyPair, BikeVariant, CompressedCiphertext, CompressionLevel};
use qasa::error::CryptoResult;
use serde::{Serialize, Deserialize};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Test vector structure for BIKE key encapsulation operations
#[derive(Debug, Serialize, Deserialize)]
pub struct BikeTestVector {
    #[serde(with = "BikeVariantDef")]
    pub variant: BikeVariant,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
    pub message: Vec<u8>,  // Optional message that was encapsulated (for documentation)
}

// Helper module for serializing BikeVariant
#[derive(Serialize, Deserialize)]
#[serde(remote = "BikeVariant")]
enum BikeVariantDef {
    Bike1Level1,
    Bike1Level3,
    Bike1Level5,
}

/// Generate a test vector for BIKE key encapsulation
pub fn generate_test_vector(
    variant: BikeVariant,
    seed: &[u8],
    message: &[u8],
) -> BikeTestVector {
    // Create a deterministic RNG from the seed
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed[..32]);
    let mut rng = ChaCha20Rng::from_seed(seed_array);
    
    // Generate a keypair using the OQS library
    let keypair = BikeKeyPair::generate(variant)
        .expect("Failed to generate BIKE keypair");
    
    // Get the public key
    let public_key = keypair.public_key();
    
    // Encapsulate to get a ciphertext and shared secret
    let (ciphertext, shared_secret) = public_key.encapsulate()
        .expect("Failed to encapsulate shared secret");
    
    BikeTestVector {
        variant,
        public_key: keypair.public_key.clone(),
        secret_key: keypair.secret_key.clone(),
        ciphertext,
        shared_secret,
        message: message.to_vec(),
    }
}

/// Standard test vectors for BIKE
pub fn standard_test_vectors() -> Vec<BikeTestVector> {
    let mut vectors = Vec::new();
    
    // Use different seeds for each test vector
    let seed_1 = b"BIKE-test-vector-seed-number-one-01";
    let seed_2 = b"BIKE-test-vector-seed-number-two-02";
    let seed_3 = b"BIKE-test-vector-seed-number-three03";
    let seed_4 = b"BIKE-test-vector-seed-number-four-04";
    let seed_5 = b"BIKE-test-vector-seed-number-five-05";
    let seed_6 = b"BIKE-test-vector-seed-number-six--06";
    
    let message = b"This is a test message for BIKE key encapsulation mechanism";
    
    // Test vector 1: BIKE-1 Level 1
    vectors.push(generate_test_vector(BikeVariant::Bike1Level1, &seed_1, message));
    
    // Test vector 2: BIKE-1 Level 3
    vectors.push(generate_test_vector(BikeVariant::Bike1Level3, &seed_2, message));
    
    // Test vector 3: BIKE-1 Level 5
    vectors.push(generate_test_vector(BikeVariant::Bike1Level5, &seed_3, message));
    
    vectors
}

/// Special case test vectors for BIKE
pub fn special_case_test_vectors() -> Vec<BikeTestVector> {
    let mut vectors = Vec::new();
    
    // Use different seeds for each test vector
    let seed_1 = b"BIKE-special-case-seed-number-one-01";
    let seed_2 = b"BIKE-special-case-seed-number-two-02";
    let seed_3 = b"BIKE-special-case-seed-number-three03";
    
    // Empty message
    let empty_message = b"";
    vectors.push(generate_test_vector(BikeVariant::Bike1Level1, &seed_1, empty_message));
    
    // Long message (not actually used in KEM, but for documentation)
    let long_message = vec![0u8; 1024];
    vectors.push(generate_test_vector(BikeVariant::Bike1Level3, &seed_2, &long_message));
    
    // Single byte message
    let single_byte_message = b"X";
    vectors.push(generate_test_vector(BikeVariant::Bike1Level5, &seed_3, single_byte_message));
    
    vectors
}

/// Negative test vectors for BIKE
pub fn negative_test_vectors() -> Vec<(BikeVariant, Vec<u8>, Vec<u8>)> {
    let mut vectors = Vec::new();
    
    // Generate a keypair for testing
    let variant = BikeVariant::Bike1Level1; // Use smallest variant for speed
    let keypair = BikeKeyPair::generate(variant).expect("Failed to generate keypair");
    let public_key = keypair.public_key();
    
    // Generate a valid ciphertext
    let (valid_ciphertext, _) = public_key.encapsulate().expect("Failed to encapsulate");
    
    // Case 1: Wrong ciphertext (all zeros)
    let wrong_ciphertext = vec![0u8; valid_ciphertext.len()];
    vectors.push((variant, keypair.secret_key.clone(), wrong_ciphertext));
    
    // Case 2: Corrupted ciphertext (flip some bits)
    let mut corrupted_ciphertext = valid_ciphertext.clone();
    corrupted_ciphertext[10] ^= 0x01;
    corrupted_ciphertext[20] ^= 0x01;
    vectors.push((variant, keypair.secret_key.clone(), corrupted_ciphertext));
    
    // Case 3: Truncated ciphertext
    let truncated_ciphertext = valid_ciphertext[..valid_ciphertext.len() - 10].to_vec();
    vectors.push((variant, keypair.secret_key.clone(), truncated_ciphertext));
    
    vectors
}

/// Compressed ciphertext test vectors for BIKE
pub fn compressed_ciphertext_test_vectors() -> Vec<(BikeVariant, Vec<u8>, Vec<u8>, CompressionLevel, Vec<u8>)> {
    let mut vectors = Vec::new();
    
    // Test with different variants and compression levels
    let variants = [
        BikeVariant::Bike1Level1,  // Use smallest variant for speed
        BikeVariant::Bike1Level5,  // Use largest variant for comprehensive testing
    ];
    
    let message = b"Test message for BIKE compressed ciphertext";
    
    for variant in &variants {
        let keypair = BikeKeyPair::generate(*variant).expect("Failed to generate keypair");
        let public_key = keypair.public_key();
        
        // Test with different compression levels
        for level in &[
            CompressionLevel::Light,
            CompressionLevel::Medium,
            CompressionLevel::High,
        ] {
            // Encapsulate with compression
            let (compressed, shared_secret) = public_key.encapsulate_compressed(*level)
                .expect("Failed to encapsulate with compression");
            
            vectors.push((
                *variant,
                keypair.secret_key.clone(),
                compressed.data().to_vec(),
                *level,
                shared_secret,
            ));
        }
    }
    
    vectors
}

/// Test function to verify BIKE test vectors
pub fn verify_test_vector(vector: &BikeTestVector) -> CryptoResult<()> {
    use qasa::bike::BikePublicKey;
    
    // Deserialize the public key
    let public_key = BikePublicKey::from_bytes(&vector.public_key)?;
    
    // Verify that decapsulation works
    let keypair = BikeKeyPair::from_bytes(&vector.secret_key)?;
    let decapsulated = keypair.decapsulate(&vector.ciphertext)?;
    
    // Check that the shared secrets match
    assert_eq!(
        decapsulated,
        vector.shared_secret,
        "Shared secret mismatch for {:?}",
        vector.variant
    );
    
    Ok(())
} 