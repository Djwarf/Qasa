//! BIKE parameter sets
//!
//! This module defines the parameter sets for different BIKE variants.

use crate::error::CryptoError;
use crate::bike::BikeVariant;

/// Parameters for a BIKE instance
#[derive(Debug, Clone, Copy)]
pub struct BikeParameters {
    /// Security level (in bits)
    pub security_level: u16,
    
    /// Code length
    pub n: usize,
    
    /// Error weight
    pub t: usize,
    
    /// Number of iterations for decoding
    pub iterations: usize,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Ciphertext size in bytes
    pub ciphertext_size: usize,
    
    /// Shared secret size in bytes
    pub shared_secret_size: usize,
    
    /// Hash function used (SHA-256, SHA-384, SHA-512)
    pub hash_function: HashFunction,
}

/// Hash functions used in BIKE
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashFunction {
    /// SHA-256 hash function
    Sha256,
    
    /// SHA-384 hash function
    Sha384,
    
    /// SHA-512 hash function
    Sha512,
}

impl BikeParameters {
    /// Get parameters for a specific BIKE variant
    pub fn for_variant(variant: BikeVariant) -> Self {
        match variant {
            BikeVariant::Bike1Level1 => Self {
                security_level: 128,
                n: 12323,
                t: 142,
                iterations: 5,
                public_key_size: 1541,
                secret_key_size: 3082,
                ciphertext_size: 1573,
                shared_secret_size: 32,
                hash_function: HashFunction::Sha256,
            },
            BikeVariant::Bike1Level3 => Self {
                security_level: 192,
                n: 24659,
                t: 199,
                iterations: 5,
                public_key_size: 3083,
                secret_key_size: 6166,
                ciphertext_size: 3115,
                shared_secret_size: 32,
                hash_function: HashFunction::Sha384,
            },
            BikeVariant::Bike1Level5 => Self {
                security_level: 256,
                n: 40973,
                t: 264,
                iterations: 5,
                public_key_size: 5122,
                secret_key_size: 10244,
                ciphertext_size: 5154,
                shared_secret_size: 32,
                hash_function: HashFunction::Sha512,
            },
        }
    }
    
    /// Calculate the approximate encapsulation time in microseconds
    pub fn approx_encapsulation_time_us(&self) -> f64 {
        match self.security_level {
            128 => 250.0,  // ~250µs for BIKE-1 Level 1
            192 => 500.0,  // ~500µs for BIKE-1 Level 3
            256 => 900.0,  // ~900µs for BIKE-1 Level 5
            _ => 500.0,    // Default estimate
        }
    }
    
    /// Calculate the approximate decapsulation time in microseconds
    pub fn approx_decapsulation_time_us(&self) -> f64 {
        match self.security_level {
            128 => 900.0,   // ~900µs for BIKE-1 Level 1
            192 => 1800.0,  // ~1800µs for BIKE-1 Level 3
            256 => 3200.0,  // ~3200µs for BIKE-1 Level 5
            _ => 1800.0,    // Default estimate
        }
    }
    
    /// Get the recommended variant for a specific environment constraint
    pub fn for_constrained_environment(
        min_security_level: u16,
        available_memory_kb: usize,
        prefer_speed: bool,
    ) -> Result<BikeVariant, CryptoError> {
        // Calculate memory requirements in KB
        let req_level1 = (3082 + 1541 + 1573) / 1024 + 1; // ~6KB for Level 1
        let req_level3 = (6166 + 3083 + 3115) / 1024 + 1; // ~12KB for Level 3
        let req_level5 = (10244 + 5122 + 5154) / 1024 + 1; // ~20KB for Level 5
        
        // Find appropriate variant based on constraints
        match min_security_level {
            0..=128 => {
                if available_memory_kb >= req_level1 {
                    Ok(BikeVariant::Bike1Level1)
                } else {
                    Err(CryptoError::invalid_parameter(
                        "available_memory_kb",
                        &format!("at least {}KB", req_level1),
                        &format!("{}KB", available_memory_kb),
                    ))
                }
            },
            129..=192 => {
                if available_memory_kb >= req_level3 {
                    Ok(BikeVariant::Bike1Level3)
                } else if available_memory_kb >= req_level1 {
                    Ok(BikeVariant::Bike1Level1) // Fallback to lower security level
                } else {
                    Err(CryptoError::invalid_parameter(
                        "available_memory_kb",
                        &format!("at least {}KB", req_level1),
                        &format!("{}KB", available_memory_kb),
                    ))
                }
            },
            193.. => {
                if available_memory_kb >= req_level5 {
                    Ok(BikeVariant::Bike1Level5)
                } else if available_memory_kb >= req_level3 {
                    Ok(BikeVariant::Bike1Level3) // Fallback to lower security level
                } else if available_memory_kb >= req_level1 {
                    Ok(BikeVariant::Bike1Level1) // Fallback to lower security level
                } else {
                    Err(CryptoError::invalid_parameter(
                        "available_memory_kb",
                        &format!("at least {}KB", req_level1),
                        &format!("{}KB", available_memory_kb),
                    ))
                }
            },
        }
    }
} 