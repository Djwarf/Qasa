//! Tests for SPHINCS+ implementation

#[cfg(test)]
mod tests {
    use crate::sphincsplus::{
        SphincsKeyPair, 
        SphincsPublicKey, 
        SphincsVariant,
        CompressionLevel,
    };
    use crate::sphincsplus::sphincsplus::is_any_sphincs_available;
    use crate::error::CryptoResult;
    use super::*;
    use crate::sphincsplus::sphincsplus::{compress_signature_medium, decompress_signature_medium, compress_signature_high, decompress_signature_high};

    /// Helper macro to skip tests if SPHINCS+ is not available
    macro_rules! skip_if_no_sphincs {
        () => {
            if !is_any_sphincs_available() {
                println!("Skipping SPHINCS+ test - algorithm not available in OQS build");
                return;
            }
        };
    }
    
    #[test]
    fn test_sphincs_key_generation() {
        skip_if_no_sphincs!();
        
        // Test key generation for each variant
        let variants = [
            SphincsVariant::Sphincs128f,
            SphincsVariant::Sphincs128s,
            SphincsVariant::Sphincs192f,
            SphincsVariant::Sphincs192s,
            SphincsVariant::Sphincs256f,
            SphincsVariant::Sphincs256s,
        ];
        
        for variant in variants.iter() {
            let result = SphincsKeyPair::generate(*variant);
            assert!(result.is_ok(), "Failed to generate key pair for {:?}", variant);
            
            let key_pair = result.unwrap();
            assert_eq!(key_pair.algorithm, *variant);
            assert_eq!(key_pair.public_key.len(), variant.public_key_size());
            assert_eq!(key_pair.secret_key.len(), variant.secret_key_size());
        }
    }
    
    #[test]
    fn test_sign_verify() {
        skip_if_no_sphincs!();
        
        // Only test with the smallest variant for speed
        let variant = SphincsVariant::Sphincs128s;
        let key_pair = SphincsKeyPair::generate(variant).unwrap();
        let message = b"Test message for SPHINCS+ signature";
        
        // Sign the message
        let signature = key_pair.sign(message).unwrap();
        
        // Verify the signature
        let is_valid = key_pair.verify(message, &signature).unwrap();
        assert!(is_valid, "Signature verification failed");
        
        // Verify with public key
        let public_key = key_pair.public_key();
        let is_valid = public_key.verify(message, &signature).unwrap();
        assert!(is_valid, "Signature verification with public key failed");
    }
    
    #[test]
    fn test_invalid_signature() {
        skip_if_no_sphincs!();
        
        let variant = SphincsVariant::Sphincs128s;
        let key_pair = SphincsKeyPair::generate(variant).unwrap();
        let message = b"Test message for SPHINCS+ signature";
        
        // Create an invalid signature
        let invalid_signature = vec![0u8; variant.signature_size()];
        
        // Verify the invalid signature
        let is_valid = key_pair.verify(message, &invalid_signature).unwrap();
        assert!(!is_valid, "Invalid signature was incorrectly verified as valid");
    }
    
    #[test]
    fn test_wrong_message() {
        skip_if_no_sphincs!();
        
        let variant = SphincsVariant::Sphincs128s;
        let key_pair = SphincsKeyPair::generate(variant).unwrap();
        let message = b"Test message for SPHINCS+ signature";
        let wrong_message = b"Wrong message for SPHINCS+ signature";
        
        // Sign the original message
        let signature = key_pair.sign(message).unwrap();
        
        // Verify with wrong message
        let is_valid = key_pair.verify(wrong_message, &signature).unwrap();
        assert!(!is_valid, "Signature verified with wrong message");
    }
    
    #[test]
    fn test_serialization() {
        skip_if_no_sphincs!();
        
        let variant = SphincsVariant::Sphincs128s;
        let key_pair = SphincsKeyPair::generate(variant).unwrap();
        
        // Serialize
        let serialized = key_pair.to_bytes().unwrap();
        
        // Deserialize
        let deserialized = SphincsKeyPair::from_bytes(&serialized).unwrap();
        
        // Verify the deserialized key pair
        assert_eq!(deserialized.algorithm, key_pair.algorithm);
        assert_eq!(deserialized.public_key, key_pair.public_key);
        assert_eq!(deserialized.secret_key, key_pair.secret_key);
    }
    
    #[test]
    fn test_public_key_serialization() {
        skip_if_no_sphincs!();
        
        let variant = SphincsVariant::Sphincs128s;
        let key_pair = SphincsKeyPair::generate(variant).unwrap();
        let public_key = key_pair.public_key();
        
        // Serialize
        let serialized = public_key.to_bytes().unwrap();
        
        // Deserialize
        let deserialized = SphincsPublicKey::from_bytes(&serialized).unwrap();
        
        // Verify the deserialized public key
        assert_eq!(deserialized.algorithm, public_key.algorithm);
        assert_eq!(deserialized.public_key, public_key.public_key);
    }
    
    #[test]
    fn test_public_key_fingerprint() {
        skip_if_no_sphincs!();
        
        let variant = SphincsVariant::Sphincs128s;
        let key_pair = SphincsKeyPair::generate(variant).unwrap();
        let public_key = key_pair.public_key();
        
        // Generate fingerprint
        let fingerprint = public_key.fingerprint();
        
        // Verify fingerprint is non-empty and has the expected format (hex string)
        assert!(!fingerprint.is_empty());
        assert_eq!(fingerprint.len(), 16); // 8 bytes as hex = 16 chars
    }
    
    #[test]
    fn test_compressed_signatures() {
        skip_if_no_sphincs!();
        
        let variant = SphincsVariant::Sphincs128s;
        let key_pair = SphincsKeyPair::generate(variant).unwrap();
        let message = b"Test message for SPHINCS+ compressed signature";
        
        // Test each compression level
        let levels = [
            CompressionLevel::None,
            CompressionLevel::Light,
            CompressionLevel::Medium,
            CompressionLevel::High,
        ];
        
        for level in levels.iter() {
            // Sign with compression
            let compressed = key_pair.sign_compressed(message, *level).unwrap();
            
            // Verify compression level is stored correctly
            assert_eq!(compressed.level(), *level);
            
            // Verify compressed signature
            let is_valid = key_pair.verify_compressed(message, &compressed).unwrap();
            assert!(is_valid, "Compressed signature verification failed for {:?}", level);
            
            // Verify with public key
            let public_key = key_pair.public_key();
            let is_valid = public_key.verify_compressed(message, &compressed).unwrap();
            assert!(is_valid, "Compressed signature verification with public key failed for {:?}", level);
            
            // For non-None compression levels, check if compression actually happened
            if *level != CompressionLevel::None {
                let compression_ratio = compressed.compression_ratio();
                println!("Compression ratio for {:?}: {:.2}", level, compression_ratio);
                
                // Verify that compression actually reduces the size
                assert!(compression_ratio < 1.0, 
                    "Compression with {:?} should reduce size, got ratio: {:.2}", 
                    level, compression_ratio);
                
                // Verify that space savings is positive
                let savings = compressed.space_savings();
                assert!(savings > 0, 
                    "Compression with {:?} should save space, saved {} bytes", 
                    level, savings);
            }
        }
    }
    
    #[test]
    fn test_parameter_selection() {
        // Test parameter selection for constrained environments
        use crate::sphincsplus::parameters::SphincsParameters;
        
        // Test with different security levels and memory constraints
        let test_cases = [
            // (min_security_level, available_memory_kb, prefer_speed, expected_result)
            (128, 8, false, Ok(SphincsVariant::Sphincs128s)),
            (128, 20, true, Ok(SphincsVariant::Sphincs128f)),
            (192, 16, false, Ok(SphincsVariant::Sphincs192s)),
            (192, 40, true, Ok(SphincsVariant::Sphincs192f)),
            (256, 30, false, Ok(SphincsVariant::Sphincs256s)),
            (256, 50, true, Ok(SphincsVariant::Sphincs256f)),
            // Test fallbacks to lower security levels when memory is constrained
            (192, 8, false, Ok(SphincsVariant::Sphincs128s)),
            (256, 16, false, Ok(SphincsVariant::Sphincs192s)),
            // Test error case when memory is too constrained
            (128, 4, false, Err(())),
        ];
        
        for (security_level, memory_kb, prefer_speed, expected) in test_cases.iter() {
            let result = SphincsParameters::for_constrained_environment(
                *security_level,
                *memory_kb,
                *prefer_speed,
            );
            
            match expected {
                Ok(expected_variant) => {
                    assert!(result.is_ok(), "Expected Ok but got Err for security_level={}, memory_kb={}, prefer_speed={}", 
                           security_level, memory_kb, prefer_speed);
                    assert_eq!(result.unwrap(), *expected_variant);
                },
                Err(_) => {
                    assert!(result.is_err(), "Expected Err but got Ok for security_level={}, memory_kb={}, prefer_speed={}", 
                           security_level, memory_kb, prefer_speed);
                }
            }
        }
    }

    #[test]
    fn test_sphincs_signature_verification() {
        skip_if_no_sphincs!();
        
        // Generate a key pair
        let key_pair = SphincsKeyPair::generate(SphincsVariant::Sphincs128f).unwrap();
        
        // Create a test message
        let message = b"This is a test message for SPHINCS+ signature";
        
        // Sign the message
        let signature = key_pair.sign(message).unwrap();
        
        // Verify with the same key pair
        let result = key_pair.verify(message, &signature).unwrap();
        assert!(result, "Signature verification failed with the same key pair");
        
        // Verify with just the public key
        let public_key = key_pair.public_key();
        let result = public_key.verify(message, &signature).unwrap();
        assert!(result, "Signature verification failed with public key");
        
        // Try with a modified message
        let modified = b"This is a modified test message for SPHINCS+ signature";
        let result = public_key.verify(modified, &signature).unwrap();
        assert!(!result, "Signature verification should fail with modified message");
        
        // Try with a modified signature
        let mut modified_sig = signature.clone();
        if !modified_sig.is_empty() {
            modified_sig[0] ^= 0xFF; // Flip bits in the first byte
        }
        let result = public_key.verify(message, &modified_sig).unwrap();
        assert!(!result, "Signature verification should fail with modified signature");
    }

    #[test]
    fn test_sphincs_serialization() {
        skip_if_no_sphincs!();
        
        // Generate a key pair
        let key_pair = SphincsKeyPair::generate(SphincsVariant::Sphincs128f).unwrap();
        
        // Serialize the key pair
        let serialized = key_pair.to_bytes().unwrap();
        
        // Deserialize the key pair
        let deserialized = SphincsKeyPair::from_bytes(&serialized).unwrap();
        
        // Verify the algorithm is preserved
        assert_eq!(key_pair.algorithm, deserialized.algorithm);
        
        // Verify the public key is preserved
        assert_eq!(key_pair.public_key, deserialized.public_key);
        
        // Verify the secret key is preserved
        assert_eq!(key_pair.secret_key, deserialized.secret_key);
        
        // Test public key serialization/deserialization
        let public_key = key_pair.public_key();
        let serialized_pub = public_key.to_bytes().unwrap();
        let deserialized_pub = SphincsPublicKey::from_bytes(&serialized_pub).unwrap();
        
        assert_eq!(public_key.algorithm, deserialized_pub.algorithm);
        assert_eq!(public_key.public_key, deserialized_pub.public_key);
    }

    #[test]
    fn test_sphincs_compression_light() {
        skip_if_no_sphincs!();
        
        // Generate a signature
        let key_pair = SphincsKeyPair::generate(SphincsVariant::Sphincs128f).unwrap();
        let message = b"Test message for compression";
        let signature = key_pair.sign(message).unwrap();
        
        // Compress with light compression
        let compressed = key_pair.sign_compressed(message, CompressionLevel::Light).unwrap();
        
        // Verify the compressed signature
        let result = key_pair.verify_compressed(message, &compressed).unwrap();
        assert!(result, "Verification of light-compressed signature failed");
        
        // Check compression ratio
        let ratio = compressed.compression_ratio();
        println!("Light compression ratio: {:.2}", ratio);
        assert!(ratio < 1.0, "Light compression should reduce size");
        
        // Check space savings
        let savings = compressed.space_savings();
        println!("Light compression saved {} bytes", savings);
        assert!(savings > 0, "Light compression should save space");
    }

    #[test]
    fn test_sphincs_compression_medium() {
        skip_if_no_sphincs!();
        
        // Generate a signature
        let key_pair = SphincsKeyPair::generate(SphincsVariant::Sphincs128f).unwrap();
        let message = b"Test message for medium compression with some repeated patterns";
        let signature = key_pair.sign(message).unwrap();
        
        // Create a signature with patterns that compress well
        let mut pattern_sig = Vec::with_capacity(signature.len());
        pattern_sig.extend_from_slice(&signature[0..100]);
        
        // Add some repeating patterns
        for _ in 0..5 {
            pattern_sig.extend_from_slice(&signature[100..200]);
        }
        pattern_sig.extend_from_slice(&signature[200..]);
        
        // Compress with medium compression
        let compressed = compress_signature_medium(&pattern_sig).unwrap();
        
        // Decompress
        let decompressed = decompress_signature_medium(&compressed).unwrap();
        
        // Verify the decompression is correct
        assert_eq!(pattern_sig, decompressed, "Medium decompression failed to restore original");
        
        // Check compression ratio
        let ratio = compressed.len() as f64 / pattern_sig.len() as f64;
        println!("Medium compression ratio: {:.2}", ratio);
    }

    #[test]
    fn test_sphincs_compression_high() {
        skip_if_no_sphincs!();
        
        // Generate a signature
        let key_pair = SphincsKeyPair::generate(SphincsVariant::Sphincs128f).unwrap();
        let message = b"Test message for high compression with many repeated patterns";
        let signature = key_pair.sign(message).unwrap();
        
        // Create a signature with patterns that compress well
        let mut pattern_sig = Vec::with_capacity(signature.len());
        pattern_sig.extend_from_slice(&signature[0..50]);
        
        // Add many repeating patterns
        for _ in 0..10 {
            pattern_sig.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
            pattern_sig.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
        pattern_sig.extend_from_slice(&signature[50..100]);
        
        // Compress with high compression
        let compressed = compress_signature_high(&pattern_sig).unwrap();
        
        // Decompress
        let decompressed = decompress_signature_high(&compressed).unwrap();
        
        // Verify the decompression is correct
        assert_eq!(pattern_sig, decompressed, "High decompression failed to restore original");
        
        // Check compression ratio
        let ratio = compressed.len() as f64 / pattern_sig.len() as f64;
        println!("High compression ratio: {:.2}", ratio);
    }

    #[test]
    fn test_sphincs_fingerprint() {
        skip_if_no_sphincs!();
        
        // Generate a key pair
        let key_pair = SphincsKeyPair::generate(SphincsVariant::Sphincs128f).unwrap();
        
        // Get the public key and its fingerprint
        let public_key = key_pair.public_key();
        let fingerprint = public_key.fingerprint();
        
        // Verify the fingerprint is non-empty
        assert!(!fingerprint.is_empty(), "Fingerprint should not be empty");
        
        // Verify the fingerprint is a hex string of the expected length (16 characters for 8 bytes)
        assert_eq!(fingerprint.len(), 16, "Fingerprint should be 16 characters long");
        
        // Generate another key pair and verify the fingerprint is different
        let key_pair2 = SphincsKeyPair::generate(SphincsVariant::Sphincs128f).unwrap();
        let public_key2 = key_pair2.public_key();
        let fingerprint2 = public_key2.fingerprint();
        
        assert_ne!(fingerprint, fingerprint2, "Different keys should have different fingerprints");
    }

    #[test]
    fn test_sphincs_all_variants() {
        skip_if_no_sphincs!();
        
        // Test all SPHINCS+ variants
        let variants = [
            SphincsVariant::Sphincs128f,
            SphincsVariant::Sphincs128s,
            SphincsVariant::Sphincs192f,
            SphincsVariant::Sphincs192s,
            SphincsVariant::Sphincs256f,
            SphincsVariant::Sphincs256s,
        ];
        
        for &variant in &variants {
            // Generate a key pair
            let key_pair = SphincsKeyPair::generate(variant).unwrap();
            
            // Create a test message
            let message = b"Testing SPHINCS+ variant";
            
            // Sign the message
            let signature = key_pair.sign(message).unwrap();
            
            // Verify the signature
            let result = key_pair.verify(message, &signature).unwrap();
            assert!(result, "Signature verification failed for variant {:?}", variant);
            
            // Check the key sizes
            assert_eq!(key_pair.public_key.len(), variant.public_key_size());
            assert_eq!(key_pair.secret_key.len(), variant.secret_key_size());
            
            // Check the security level
            let level = variant.security_level();
            match variant {
                SphincsVariant::Sphincs128f | SphincsVariant::Sphincs128s => assert_eq!(level, 1),
                SphincsVariant::Sphincs192f | SphincsVariant::Sphincs192s => assert_eq!(level, 3),
                SphincsVariant::Sphincs256f | SphincsVariant::Sphincs256s => assert_eq!(level, 5),
            }
        }
    }
}
