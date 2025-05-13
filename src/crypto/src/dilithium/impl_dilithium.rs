// Implementation of the CRYSTALS-Dilithium algorithm
// This file contains code moved from src/dilithium.rs

use oqs::sig::{Algorithm, Sig};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::CryptoError;

/// CRYSTALS-Dilithium key pair for digital signatures
/// 
/// This implementation uses the CRYSTALS-Dilithium algorithm, a lattice-based
/// digital signature scheme that is believed to be secure against 
/// quantum computer attacks.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DilithiumKeyPair {
    /// Public key for signature verification
    pub public_key: Vec<u8>,
    /// Secret key for signature generation
    pub secret_key: Vec<u8>,
    /// The algorithm variant (Dilithium2, Dilithium3, or Dilithium5)
    pub algorithm: DilithiumVariant,
}

/// Public key only version of DilithiumKeyPair for sharing with others
#[derive(Serialize, Deserialize, Clone)]
pub struct DilithiumPublicKey {
    /// Public key for signature verification
    pub public_key: Vec<u8>,
    /// The algorithm variant (Dilithium2, Dilithium3, or Dilithium5)
    pub algorithm: DilithiumVariant,
}

/// CRYSTALS-Dilithium algorithm variants with different security levels
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DilithiumVariant {
    /// Dilithium2 (NIST security level 2)
    Dilithium2,
    /// Dilithium3 (NIST security level 3, recommended)
    Dilithium3,
    /// Dilithium5 (NIST security level 5)
    Dilithium5,
}

impl fmt::Display for DilithiumVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DilithiumVariant::Dilithium2 => write!(f, "Dilithium2"),
            DilithiumVariant::Dilithium3 => write!(f, "Dilithium3"),
            DilithiumVariant::Dilithium5 => write!(f, "Dilithium5"),
        }
    }
}

impl DilithiumVariant {
    /// Get the OQS algorithm name for this variant
    fn oqs_algorithm(&self) -> Algorithm {
        match self {
            DilithiumVariant::Dilithium2 => Algorithm::Dilithium2,
            DilithiumVariant::Dilithium3 => Algorithm::Dilithium3,
            DilithiumVariant::Dilithium5 => Algorithm::Dilithium5,
        }
    }
    
    /// Get the security level of this variant
    pub fn security_level(&self) -> u8 {
        match self {
            DilithiumVariant::Dilithium2 => 2,
            DilithiumVariant::Dilithium3 => 3,
            DilithiumVariant::Dilithium5 => 5,
        }
    }
    
    /// Get the public key size for this variant in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            DilithiumVariant::Dilithium2 => 1312,
            DilithiumVariant::Dilithium3 => 1952,
            DilithiumVariant::Dilithium5 => 2592,
        }
    }
    
    /// Get the secret key size for this variant in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            DilithiumVariant::Dilithium2 => 2528,
            DilithiumVariant::Dilithium3 => 4000,
            DilithiumVariant::Dilithium5 => 4864,
        }
    }
    
    /// Get the signature size for this variant in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            DilithiumVariant::Dilithium2 => 2420,
            DilithiumVariant::Dilithium3 => 3293,
            DilithiumVariant::Dilithium5 => 4595,
        }
    }
}

impl DilithiumKeyPair {
    /// Generate a new key pair with the specified variant
    ///
    /// # Arguments
    ///
    /// * `variant` - The Dilithium variant to use
    ///
    /// # Returns
    ///
    /// A new key pair or an error if key generation failed
    pub fn generate(variant: DilithiumVariant) -> Result<Self, CryptoError> {
        let alg = variant.oqs_algorithm();
        let sig = Sig::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;
        
        let (public_key, secret_key) = sig.keypair()
            .map_err(|e| CryptoError::KeyGenerationError(e.to_string()))?;
            
        Ok(Self {
            public_key: public_key.into_vec(),
            secret_key: secret_key.into_vec(),
            algorithm: variant,
        })
    }
    
    /// Sign a message with this key pair's secret key
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// The signature or an error if signing failed
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let alg = self.algorithm.oqs_algorithm();
        let sig = Sig::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;
        
        // Create a secret key from bytes
        let sk = sig.secret_key_from_bytes(&self.secret_key)
            .ok_or_else(|| CryptoError::SignatureGenerationError("Failed to create secret key from bytes".to_string()))?;
            
        let signature = sig.sign(message, &sk)
            .map_err(|e| CryptoError::SignatureGenerationError(e.to_string()))?;
            
        Ok(signature.into_vec())
    }
    
    /// Verify a signature with this key pair's public key
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        Self::verify_with_public_key(self.algorithm, &self.public_key, message, signature)
    }
    
    /// Verify a signature with a public key
    ///
    /// # Arguments
    ///
    /// * `variant` - The Dilithium variant
    /// * `public_key` - The public key to use for verification
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    pub fn verify_with_public_key(
        variant: DilithiumVariant,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let alg = variant.oqs_algorithm();
        let sig = Sig::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;
        
        // Create a public key from bytes
        let pk = sig.public_key_from_bytes(public_key)
            .ok_or_else(|| CryptoError::SignatureVerificationError("Failed to create public key from bytes".to_string()))?;
            
        // Create a signature from bytes
        let sig_bytes = sig.signature_from_bytes(signature)
            .ok_or_else(|| CryptoError::SignatureVerificationError("Failed to create signature from bytes".to_string()))?;
            
        // Verify the signature
        match sig.verify(message, &sig_bytes, &pk) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Extract the public key from this key pair
    ///
    /// # Returns
    ///
    /// A DilithiumPublicKey containing only the public key information
    pub fn public_key(&self) -> DilithiumPublicKey {
        DilithiumPublicKey {
            public_key: self.public_key.clone(),
            algorithm: self.algorithm,
        }
    }
}

// Rest of the implementation would be here 