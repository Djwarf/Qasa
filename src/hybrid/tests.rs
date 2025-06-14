//! Tests for hybrid cryptographic modes

#[cfg(test)]
mod tests {
    use super::super::hybrid_kem::{
        HybridKemKeyPair,
        HybridKemPublicKey,
        HybridKemVariant,
        ClassicalKemAlgorithm,
        PostQuantumKemAlgorithm,
    };
    use crate::kyber::KyberVariant;
    use crate::bike::BikeVariant;
    
    #[test]
    fn test_hybrid_kem_key_generation() {
        // Test key generation for each variant combination
        let variants = [
            HybridKemVariant {
                classical: ClassicalKemAlgorithm::X25519,
                post_quantum: PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber768),
            },
            HybridKemVariant {
                classical: ClassicalKemAlgorithm::X25519,
                post_quantum: PostQuantumKemAlgorithm::Bike(BikeVariant::Bike1Level1),
            },
        ];
        
        for variant in variants.iter() {
            let result = HybridKemKeyPair::generate(*variant);
            assert!(result.is_ok(), "Failed to generate key pair for {:?}", variant);
            
            let key_pair = result.unwrap();
            assert_eq!(key_pair.algorithm, *variant);
        }
    }
    
    #[test]
    fn test_hybrid_kem_encapsulate_decapsulate() {
        // Test with X25519 + Kyber768
        let variant = HybridKemVariant {
            classical: ClassicalKemAlgorithm::X25519,
            post_quantum: PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber768),
        };
        
        // Generate key pair
        let key_pair = HybridKemKeyPair::generate(variant).unwrap();
        
        // Get public key
        let public_key = key_pair.public_key().unwrap();
        
        // Encapsulate to get ciphertext and shared secret
        let (ciphertext, shared_secret1) = public_key.encapsulate().unwrap();
        
        // Decapsulate to recover shared secret
        let shared_secret2 = key_pair.decapsulate(&ciphertext).unwrap();
        
        // Verify shared secrets match
        assert_eq!(shared_secret1, shared_secret2);
    }
    
    #[test]
    fn test_hybrid_kem_serialization() {
        // Test with X25519 + Kyber768
        let variant = HybridKemVariant {
            classical: ClassicalKemAlgorithm::X25519,
            post_quantum: PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber768),
        };
        
        // Generate key pair
        let key_pair = HybridKemKeyPair::generate(variant).unwrap();
        
        // Serialize
        let serialized = key_pair.to_bytes().unwrap();
        
        // Deserialize
        let deserialized = HybridKemKeyPair::from_bytes(&serialized).unwrap();
        
        // Verify the deserialized key pair
        assert_eq!(deserialized.algorithm, key_pair.algorithm);
        assert_eq!(deserialized.classical_key, key_pair.classical_key);
        assert_eq!(deserialized.post_quantum_key, key_pair.post_quantum_key);
    }
    
    #[test]
    fn test_hybrid_kem_public_key_serialization() {
        // Test with X25519 + Kyber768
        let variant = HybridKemVariant {
            classical: ClassicalKemAlgorithm::X25519,
            post_quantum: PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber768),
        };
        
        // Generate key pair
        let key_pair = HybridKemKeyPair::generate(variant).unwrap();
        
        // Get public key
        let public_key = key_pair.public_key().unwrap();
        
        // Serialize
        let serialized = public_key.to_bytes().unwrap();
        
        // Deserialize
        let deserialized = HybridKemPublicKey::from_bytes(&serialized).unwrap();
        
        // Verify the deserialized public key
        assert_eq!(deserialized.algorithm, public_key.algorithm);
        assert_eq!(deserialized.classical_key, public_key.classical_key);
        assert_eq!(deserialized.post_quantum_key, public_key.post_quantum_key);
    }
    
    #[test]
    fn test_hybrid_kem_ciphertext_serialization() {
        // Test with X25519 + Kyber768
        let variant = HybridKemVariant {
            classical: ClassicalKemAlgorithm::X25519,
            post_quantum: PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber768),
        };
        
        // Generate key pair
        let key_pair = HybridKemKeyPair::generate(variant).unwrap();
        
        // Get public key
        let public_key = key_pair.public_key().unwrap();
        
        // Encapsulate
        let (ciphertext, _) = public_key.encapsulate().unwrap();
        
        // Serialize
        let serialized = ciphertext.to_bytes().unwrap();
        
        // Deserialize
        let deserialized = super::super::hybrid_kem::HybridKemCiphertext::from_bytes(&serialized).unwrap();
        
        // Verify the deserialized ciphertext
        assert_eq!(deserialized.algorithm, ciphertext.algorithm);
        assert_eq!(deserialized.classical_ciphertext, ciphertext.classical_ciphertext);
        assert_eq!(deserialized.post_quantum_ciphertext, ciphertext.post_quantum_ciphertext);
    }
    
    #[test]
    fn test_hybrid_kem_fingerprint() {
        // Test with X25519 + Kyber768
        let variant = HybridKemVariant {
            classical: ClassicalKemAlgorithm::X25519,
            post_quantum: PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber768),
        };
        
        // Generate key pair
        let key_pair = HybridKemKeyPair::generate(variant).unwrap();
        
        // Get public key
        let public_key = key_pair.public_key().unwrap();
        
        // Generate fingerprint
        let fingerprint = public_key.fingerprint();
        
        // Verify fingerprint is non-empty and has the expected format (hex string)
        assert!(!fingerprint.is_empty());
        assert_eq!(fingerprint.len(), 16); // 8 bytes as hex = 16 chars
    }
} 