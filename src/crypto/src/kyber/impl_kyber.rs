// Implementation of the CRYSTALS-Kyber algorithm
// This file contains code moved from src/kyber.rs

use oqs::kem::{Algorithm, Kem};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::CryptoError;
use crate::utils;

/// CRYSTALS-Kyber key pair for key encapsulation mechanisms (KEM)
/// 
/// This implementation uses the CRYSTALS-Kyber algorithm, a lattice-based
/// key encapsulation mechanism that is believed to be secure against 
/// quantum computer attacks.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KyberKeyPair {
    /// Public key for encapsulation
    pub public_key: Vec<u8>,
    /// Secret key for decapsulation
    pub secret_key: Vec<u8>,
    /// The algorithm variant (Kyber512, Kyber768, or Kyber1024)
    pub algorithm: KyberVariant,
}

/// Public key only version of KyberKeyPair for sharing with others
#[derive(Serialize, Deserialize, Clone)]
pub struct KyberPublicKey {
    /// Public key for encapsulation
    pub public_key: Vec<u8>,
    /// The algorithm variant (Kyber512, Kyber768, or Kyber1024)
    pub algorithm: KyberVariant,
}

/// CRYSTALS-Kyber algorithm variants with different security levels
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KyberVariant {
    /// Kyber512 (NIST security level 1)
    Kyber512,
    /// Kyber768 (NIST security level 3, recommended)
    Kyber768,
    /// Kyber1024 (NIST security level 5)
    Kyber1024,
}

impl fmt::Display for KyberVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KyberVariant::Kyber512 => write!(f, "Kyber512"),
            KyberVariant::Kyber768 => write!(f, "Kyber768"),
            KyberVariant::Kyber1024 => write!(f, "Kyber1024"),
        }
    }
}

impl KyberVariant {
    /// Get the OQS algorithm for this variant
    fn oqs_algorithm(&self) -> Algorithm {
        match self {
            KyberVariant::Kyber512 => Algorithm::Kyber512,
            KyberVariant::Kyber768 => Algorithm::Kyber768,
            KyberVariant::Kyber1024 => Algorithm::Kyber1024,
        }
    }
    
    /// Get the security level of this variant
    pub fn security_level(&self) -> u8 {
        match self {
            KyberVariant::Kyber512 => 1,
            KyberVariant::Kyber768 => 3,
            KyberVariant::Kyber1024 => 5,
        }
    }
    
    /// Get the public key size for this variant in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            KyberVariant::Kyber512 => 800,
            KyberVariant::Kyber768 => 1184,
            KyberVariant::Kyber1024 => 1568,
        }
    }
    
    /// Get the secret key size for this variant in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            KyberVariant::Kyber512 => 1632,
            KyberVariant::Kyber768 => 2400,
            KyberVariant::Kyber1024 => 3168,
        }
    }
    
    /// Get the ciphertext size for this variant in bytes
    pub fn ciphertext_size(&self) -> usize {
        match self {
            KyberVariant::Kyber512 => 768,
            KyberVariant::Kyber768 => 1088,
            KyberVariant::Kyber1024 => 1568,
        }
    }
    
    /// Get the shared secret size in bytes (same for all variants)
    pub fn shared_secret_size(&self) -> usize {
        32 // All Kyber variants use 32-byte shared secrets
    }
}

impl KyberKeyPair {
    /// Generate a new Kyber key pair with the specified variant
    ///
    /// # Arguments
    ///
    /// * `variant` - The Kyber variant to use (Kyber512, Kyber768, or Kyber1024)
    ///
    /// # Returns
    ///
    /// A new KyberKeyPair or an error if key generation failed
    pub fn generate(variant: KyberVariant) -> Result<Self, CryptoError> {
        let alg = variant.oqs_algorithm();
        let kyber = Kem::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;
        
        let (public_key, secret_key) = kyber.keypair()
            .map_err(|e| CryptoError::KeyGenerationError(e.to_string()))?;
            
        Ok(Self {
            public_key: public_key.into_vec(),
            secret_key: secret_key.into_vec(),
            algorithm: variant,
        })
    }
    
    /// Encapsulate a shared secret using this key pair's public key
    ///
    /// This generates a shared secret and encapsulates it with the public key.
    /// Both the ciphertext and shared secret are returned.
    ///
    /// # Returns
    ///
    /// A tuple containing (ciphertext, shared_secret) or an error
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let alg = self.algorithm.oqs_algorithm();
        let kyber = Kem::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;
        
        // Create a public key from bytes using the Kem instance
        let pk = kyber.public_key_from_bytes(&self.public_key)
            .ok_or_else(|| CryptoError::EncapsulationError("Failed to create public key from bytes".to_string()))?;
        
        let (ciphertext, shared_secret) = kyber.encapsulate(&pk)
            .map_err(|e| CryptoError::EncapsulationError(e.to_string()))?;
            
        Ok((ciphertext.into_vec(), shared_secret.into_vec()))
    }
    
    /// Decapsulate a shared secret using this key pair's secret key
    ///
    /// This takes a ciphertext and extracts the shared secret using the secret key.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext containing the encapsulated shared secret
    ///
    /// # Returns
    ///
    /// The shared secret or an error
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let alg = self.algorithm.oqs_algorithm();
        let kyber = Kem::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;
        
        // Create a secret key from bytes using the Kem instance
        let sk = kyber.secret_key_from_bytes(&self.secret_key)
            .ok_or_else(|| CryptoError::DecapsulationError("Failed to create secret key from bytes".to_string()))?;
        
        // Create a ciphertext from bytes using the Kem instance
        let ct = kyber.ciphertext_from_bytes(ciphertext)
            .ok_or_else(|| CryptoError::DecapsulationError("Failed to create ciphertext from bytes".to_string()))?;
        
        let shared_secret = kyber.decapsulate(&sk, &ct)
            .map_err(|e| CryptoError::DecapsulationError(e.to_string()))?;
        
        Ok(shared_secret.into_vec())
    }
    
    /// Extract the public key from this key pair
    ///
    /// This is useful when you need to share your public key with others
    /// while keeping the secret key private.
    ///
    /// # Returns
    ///
    /// A KyberPublicKey containing only the public key information
    pub fn public_key(&self) -> KyberPublicKey {
        KyberPublicKey {
            public_key: self.public_key.clone(),
            algorithm: self.algorithm,
        }
    }
}

// Rest of the implementation would be here 