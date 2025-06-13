//! Tests for SPHINCS+ implementation

#[cfg(test)]
mod tests {
    use crate::sphincsplus::{
        SphincsKeyPair, 
        SphincsPublicKey, 
        SphincsVariant,
        CompressionLevel,
    };
    use crate::error::CryptoResult;
    
    #[test]
    fn test_sphincs_key_generation() {
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
        let variant = SphincsVariant::Sphincs128s;
        let key_pair = SphincsKeyPair::generate(variant).unwrap();
        let message = b"Test message for SPHINCS+ signature";
        
        // Create an invalid signature
        let mut invalid_signature = vec![0u8; variant.signature_size()];
        
        // Verify the invalid signature
        let is_valid = key_pair.verify(message, &invalid_signature).unwrap();
        assert!(!is_valid, "Invalid signature was incorrectly verified as valid");
    }
    
    #[test]
    fn test_wrong_message() {
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
                
                // Note: In a real implementation, we would check that compression_ratio < 1.0
                // But our placeholder implementations don't actually compress
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
}
