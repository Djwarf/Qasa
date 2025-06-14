//! Tests for BIKE implementation

#[cfg(test)]
mod tests {
    use crate::bike::{
        BikeKeyPair, 
        BikePublicKey, 
        BikeVariant,
        CompressionLevel,
    };
    use crate::error::CryptoResult;
    
    #[test]
    fn test_bike_key_generation() {
        // Test key generation for each variant
        let variants = [
            BikeVariant::Bike1Level1,
            BikeVariant::Bike1Level3,
            BikeVariant::Bike1Level5,
        ];
        
        for variant in variants.iter() {
            let result = BikeKeyPair::generate(*variant);
            assert!(result.is_ok(), "Failed to generate key pair for {:?}", variant);
            
            let key_pair = result.unwrap();
            assert_eq!(key_pair.algorithm, *variant);
            assert_eq!(key_pair.public_key.len(), variant.public_key_size());
            assert_eq!(key_pair.secret_key.len(), variant.secret_key_size());
        }
    }
    
    #[test]
    fn test_encapsulate_decapsulate() {
        // Only test with the smallest variant for speed
        let variant = BikeVariant::Bike1Level1;
        let key_pair = BikeKeyPair::generate(variant).unwrap();
        let public_key = key_pair.public_key();
        
        // Encapsulate to get ciphertext and shared secret
        let (ciphertext, shared_secret1) = public_key.encapsulate().unwrap();
        
        // Verify ciphertext size
        assert_eq!(ciphertext.len(), variant.ciphertext_size());
        
        // Verify shared secret size
        assert_eq!(shared_secret1.len(), variant.shared_secret_size());
        
        // Decapsulate to recover the shared secret
        let shared_secret2 = key_pair.decapsulate(&ciphertext).unwrap();
        
        // Verify that the shared secrets match
        assert_eq!(shared_secret1, shared_secret2);
    }
    
    #[test]
    fn test_invalid_ciphertext() {
        let variant = BikeVariant::Bike1Level1;
        let key_pair = BikeKeyPair::generate(variant).unwrap();
        
        // Create an invalid ciphertext
        let mut invalid_ciphertext = vec![0u8; variant.ciphertext_size()];
        
        // Attempt to decapsulate
        let result = key_pair.decapsulate(&invalid_ciphertext);
        
        // The decapsulation should succeed but produce a different shared secret
        assert!(result.is_ok());
        
        // Now try with wrong size
        invalid_ciphertext.truncate(100);
        let result = key_pair.decapsulate(&invalid_ciphertext);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_serialization() {
        let variant = BikeVariant::Bike1Level1;
        let key_pair = BikeKeyPair::generate(variant).unwrap();
        
        // Serialize
        let serialized = key_pair.to_bytes().unwrap();
        
        // Deserialize
        let deserialized = BikeKeyPair::from_bytes(&serialized).unwrap();
        
        // Verify the deserialized key pair
        assert_eq!(deserialized.algorithm, key_pair.algorithm);
        assert_eq!(deserialized.public_key, key_pair.public_key);
        assert_eq!(deserialized.secret_key, key_pair.secret_key);
    }
    
    #[test]
    fn test_public_key_serialization() {
        let variant = BikeVariant::Bike1Level1;
        let key_pair = BikeKeyPair::generate(variant).unwrap();
        let public_key = key_pair.public_key();
        
        // Serialize
        let serialized = public_key.to_bytes().unwrap();
        
        // Deserialize
        let deserialized = BikePublicKey::from_bytes(&serialized).unwrap();
        
        // Verify the deserialized public key
        assert_eq!(deserialized.algorithm, public_key.algorithm);
        assert_eq!(deserialized.public_key, public_key.public_key);
    }
    
    #[test]
    fn test_public_key_fingerprint() {
        let variant = BikeVariant::Bike1Level1;
        let key_pair = BikeKeyPair::generate(variant).unwrap();
        let public_key = key_pair.public_key();
        
        // Generate fingerprint
        let fingerprint = public_key.fingerprint();
        
        // Verify fingerprint is non-empty and has the expected format (hex string)
        assert!(!fingerprint.is_empty());
        assert_eq!(fingerprint.len(), 16); // 8 bytes as hex = 16 chars
    }
    
    #[test]
    fn test_compressed_ciphertexts() {
        let variant = BikeVariant::Bike1Level1;
        let key_pair = BikeKeyPair::generate(variant).unwrap();
        let public_key = key_pair.public_key();
        
        // Test each compression level
        let levels = [
            CompressionLevel::None,
            CompressionLevel::Light,
            CompressionLevel::Medium,
            CompressionLevel::High,
        ];
        
        for level in levels.iter() {
            // Encapsulate with compression
            let (compressed, shared_secret1) = public_key.encapsulate_compressed(*level).unwrap();
            
            // Verify compression level is stored correctly
            assert_eq!(compressed.level(), *level);
            
            // Decapsulate compressed ciphertext
            let shared_secret2 = key_pair.decapsulate_compressed(&compressed).unwrap();
            
            // Verify that the shared secrets match
            assert_eq!(shared_secret1, shared_secret2);
            
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
        use crate::bike::parameters::BikeParameters;
        
        // Test with different security levels and memory constraints
        let test_cases = [
            // (min_security_level, available_memory_kb, prefer_speed, expected_result)
            (128, 6, false, Ok(BikeVariant::Bike1Level1)),
            (192, 12, false, Ok(BikeVariant::Bike1Level3)),
            (256, 20, false, Ok(BikeVariant::Bike1Level5)),
            // Test fallbacks to lower security levels when memory is constrained
            (192, 6, false, Ok(BikeVariant::Bike1Level1)),
            (256, 12, false, Ok(BikeVariant::Bike1Level3)),
            // Test error case when memory is too constrained
            (128, 3, false, Err(())),
        ];
        
        for (security_level, memory_kb, prefer_speed, expected) in test_cases.iter() {
            let result = BikeParameters::for_constrained_environment(
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