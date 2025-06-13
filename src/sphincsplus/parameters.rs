//! SPHINCS+ parameter sets
//!
//! This module defines the parameter sets for different SPHINCS+ variants.

use crate::error::CryptoError;
use crate::sphincsplus::SphincsVariant;

/// Parameters for a SPHINCS+ instance
#[derive(Debug, Clone, Copy)]
pub struct SphincsParameters {
    /// Security level (in bits)
    pub security_level: u16,
    
    /// Height of the hypertree
    pub h: u8,
    
    /// Height of the trees
    pub d: u8,
    
    /// Winternitz parameter
    pub w: u8,
    
    /// Number of message digest bits
    pub n: u8,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Signature size in bytes
    pub signature_size: usize,
    
    /// Hash function used (SHA-256, SHAKE256, etc.)
    pub hash_function: HashFunction,
    
    /// Optimization mode (fast vs. small)
    pub optimization: OptimizationMode,
}

/// Hash functions used in SPHINCS+
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashFunction {
    /// SHA-256 hash function
    Sha256,
    
    /// SHAKE-256 hash function
    Shake256,
    
    /// Haraka hash function
    Haraka,
}

/// Optimization modes for SPHINCS+
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OptimizationMode {
    /// Optimized for speed
    Fast,
    
    /// Optimized for size
    Small,
}

impl SphincsParameters {
    /// Get parameters for a specific SPHINCS+ variant
    pub fn for_variant(variant: SphincsVariant) -> Self {
        match variant {
            SphincsVariant::Sphincs128f => Self {
                security_level: 128,
                h: 16,
                d: 22,
                w: 16,
                n: 16,
                public_key_size: 32,
                secret_key_size: 64,
                signature_size: 17088,
                hash_function: HashFunction::Sha256,
                optimization: OptimizationMode::Fast,
            },
            SphincsVariant::Sphincs128s => Self {
                security_level: 128,
                h: 16,
                d: 7,
                w: 16,
                n: 16,
                public_key_size: 32,
                secret_key_size: 64,
                signature_size: 7856,
                hash_function: HashFunction::Sha256,
                optimization: OptimizationMode::Small,
            },
            SphincsVariant::Sphincs192f => Self {
                security_level: 192,
                h: 24,
                d: 33,
                w: 16,
                n: 24,
                public_key_size: 48,
                secret_key_size: 96,
                signature_size: 35664,
                hash_function: HashFunction::Shake256,
                optimization: OptimizationMode::Fast,
            },
            SphincsVariant::Sphincs192s => Self {
                security_level: 192,
                h: 24,
                d: 8,
                w: 16,
                n: 24,
                public_key_size: 48,
                secret_key_size: 96,
                signature_size: 16224,
                hash_function: HashFunction::Shake256,
                optimization: OptimizationMode::Small,
            },
            SphincsVariant::Sphincs256f => Self {
                security_level: 256,
                h: 32,
                d: 68,
                w: 16,
                n: 32,
                public_key_size: 64,
                secret_key_size: 128,
                signature_size: 49856,
                hash_function: HashFunction::Shake256,
                optimization: OptimizationMode::Fast,
            },
            SphincsVariant::Sphincs256s => Self {
                security_level: 256,
                h: 32,
                d: 14,
                w: 16,
                n: 32,
                public_key_size: 64,
                secret_key_size: 128,
                signature_size: 29792,
                hash_function: HashFunction::Shake256,
                optimization: OptimizationMode::Small,
            },
        }
    }
    
    /// Calculate the approximate signing time in milliseconds
    pub fn approx_signing_time_ms(&self) -> f64 {
        match self.optimization {
            OptimizationMode::Fast => {
                // Fast variants prioritize signing speed
                match self.security_level {
                    128 => 3.5,   // ~3.5ms for SPHINCS+-128f
                    192 => 7.2,   // ~7.2ms for SPHINCS+-192f
                    256 => 14.5,  // ~14.5ms for SPHINCS+-256f
                    _ => 10.0,    // Default estimate
                }
            },
            OptimizationMode::Small => {
                // Small variants have larger signing times
                match self.security_level {
                    128 => 12.8,  // ~12.8ms for SPHINCS+-128s
                    192 => 42.5,  // ~42.5ms for SPHINCS+-192s
                    256 => 85.3,  // ~85.3ms for SPHINCS+-256s
                    _ => 50.0,    // Default estimate
                }
            },
        }
    }
    
    /// Calculate the approximate verification time in milliseconds
    pub fn approx_verify_time_ms(&self) -> f64 {
        // Verification is generally faster than signing
        match self.optimization {
            OptimizationMode::Fast => {
                match self.security_level {
                    128 => 0.6,   // ~0.6ms for SPHINCS+-128f
                    192 => 1.2,   // ~1.2ms for SPHINCS+-192f
                    256 => 2.1,   // ~2.1ms for SPHINCS+-256f
                    _ => 1.5,     // Default estimate
                }
            },
            OptimizationMode::Small => {
                match self.security_level {
                    128 => 1.8,   // ~1.8ms for SPHINCS+-128s
                    192 => 3.5,   // ~3.5ms for SPHINCS+-192s
                    256 => 6.2,   // ~6.2ms for SPHINCS+-256s
                    _ => 4.0,     // Default estimate
                }
            },
        }
    }
    
    /// Get the recommended variant for a specific environment constraint
    pub fn for_constrained_environment(
        min_security_level: u16,
        available_memory_kb: usize,
        prefer_speed: bool,
    ) -> Result<SphincsVariant, CryptoError> {
        // Calculate memory requirements in KB
        let req_128f = 17088 / 1024 + 1; // ~17KB for signature
        let req_128s = 7856 / 1024 + 1;  // ~8KB for signature
        let req_192f = 35664 / 1024 + 1; // ~35KB for signature
        let req_192s = 16224 / 1024 + 1; // ~16KB for signature
        let req_256f = 49856 / 1024 + 1; // ~49KB for signature
        let req_256s = 29792 / 1024 + 1; // ~30KB for signature
        
        // Find appropriate variant based on constraints
        match min_security_level {
            0..=128 => {
                if available_memory_kb >= req_128f && prefer_speed {
                    Ok(SphincsVariant::Sphincs128f)
                } else if available_memory_kb >= req_128s {
                    Ok(SphincsVariant::Sphincs128s)
                } else {
                    Err(CryptoError::invalid_parameter(
                        "available_memory_kb",
                        &format!("at least {}KB", req_128s),
                        &format!("{}KB", available_memory_kb),
                    ))
                }
            },
            129..=192 => {
                if available_memory_kb >= req_192f && prefer_speed {
                    Ok(SphincsVariant::Sphincs192f)
                } else if available_memory_kb >= req_192s {
                    Ok(SphincsVariant::Sphincs192s)
                } else if available_memory_kb >= req_128f && prefer_speed {
                    Ok(SphincsVariant::Sphincs128f) // Fallback to lower security level
                } else if available_memory_kb >= req_128s {
                    Ok(SphincsVariant::Sphincs128s) // Fallback to lower security level
                } else {
                    Err(CryptoError::invalid_parameter(
                        "available_memory_kb",
                        &format!("at least {}KB", req_128s),
                        &format!("{}KB", available_memory_kb),
                    ))
                }
            },
            193.. => {
                if available_memory_kb >= req_256f && prefer_speed {
                    Ok(SphincsVariant::Sphincs256f)
                } else if available_memory_kb >= req_256s {
                    Ok(SphincsVariant::Sphincs256s)
                } else if available_memory_kb >= req_192f && prefer_speed {
                    Ok(SphincsVariant::Sphincs192f) // Fallback to lower security level
                } else if available_memory_kb >= req_192s {
                    Ok(SphincsVariant::Sphincs192s) // Fallback to lower security level
                } else if available_memory_kb >= req_128f && prefer_speed {
                    Ok(SphincsVariant::Sphincs128f) // Fallback to lower security level
                } else if available_memory_kb >= req_128s {
                    Ok(SphincsVariant::Sphincs128s) // Fallback to lower security level
                } else {
                    Err(CryptoError::invalid_parameter(
                        "available_memory_kb",
                        &format!("at least {}KB", req_128s),
                        &format!("{}KB", available_memory_kb),
                    ))
                }
            },
        }
    }
} 