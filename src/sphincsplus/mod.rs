//! SPHINCS+ post-quantum signature algorithm implementation
//! 
//! SPHINCS+ is a stateless hash-based signature scheme that was selected by NIST
//! as part of the post-quantum cryptography standardization process.
//! 
//! This module provides an implementation of SPHINCS+ with various parameter sets
//! for different security levels and performance characteristics.

mod sphincsplus;
mod parameters;
mod tests;

pub use sphincsplus::{
    SphincsKeyPair, 
    SphincsPublicKey, 
    SphincsVariant,
    CompressedSignature,
    CompressionLevel,
    compress_signature_light,
    compress_signature_medium,
    compress_signature_high,
    decompress_signature_light,
    decompress_signature_medium,
    decompress_signature_high
};

/// Serializable version of SphincsVariant for storage
#[derive(serde::Serialize, serde::Deserialize)]
pub enum SphincsVariantSerde {
    /// SPHINCS+-128f-simple (fast variant, NIST security level 1)
    Sphincs128f,
    /// SPHINCS+-128s-simple (small variant, NIST security level 1)
    Sphincs128s,
    /// SPHINCS+-192f-simple (fast variant, NIST security level 3)
    Sphincs192f,
    /// SPHINCS+-192s-simple (small variant, NIST security level 3)
    Sphincs192s,
    /// SPHINCS+-256f-simple (fast variant, NIST security level 5)
    Sphincs256f,
    /// SPHINCS+-256s-simple (small variant, NIST security level 5)
    Sphincs256s,
}

impl From<SphincsVariant> for SphincsVariantSerde {
    fn from(variant: SphincsVariant) -> Self {
        match variant {
            SphincsVariant::Sphincs128f => SphincsVariantSerde::Sphincs128f,
            SphincsVariant::Sphincs128s => SphincsVariantSerde::Sphincs128s,
            SphincsVariant::Sphincs192f => SphincsVariantSerde::Sphincs192f,
            SphincsVariant::Sphincs192s => SphincsVariantSerde::Sphincs192s,
            SphincsVariant::Sphincs256f => SphincsVariantSerde::Sphincs256f,
            SphincsVariant::Sphincs256s => SphincsVariantSerde::Sphincs256s,
        }
    }
}

impl From<SphincsVariantSerde> for SphincsVariant {
    fn from(variant: SphincsVariantSerde) -> Self {
        match variant {
            SphincsVariantSerde::Sphincs128f => SphincsVariant::Sphincs128f,
            SphincsVariantSerde::Sphincs128s => SphincsVariant::Sphincs128s,
            SphincsVariantSerde::Sphincs192f => SphincsVariant::Sphincs192f,
            SphincsVariantSerde::Sphincs192s => SphincsVariant::Sphincs192s,
            SphincsVariantSerde::Sphincs256f => SphincsVariant::Sphincs256f,
            SphincsVariantSerde::Sphincs256s => SphincsVariant::Sphincs256s,
        }
    }
}

/// Serializable version of CompressionLevel for storage
#[derive(serde::Serialize, serde::Deserialize)]
pub enum CompressionLevelSerde {
    None,
    Light,
    Medium,
    High,
}

impl From<CompressionLevel> for CompressionLevelSerde {
    fn from(level: CompressionLevel) -> Self {
        match level {
            CompressionLevel::None => CompressionLevelSerde::None,
            CompressionLevel::Light => CompressionLevelSerde::Light,
            CompressionLevel::Medium => CompressionLevelSerde::Medium,
            CompressionLevel::High => CompressionLevelSerde::High,
        }
    }
}

impl From<CompressionLevelSerde> for CompressionLevel {
    fn from(level: CompressionLevelSerde) -> Self {
        match level {
            CompressionLevelSerde::None => CompressionLevel::None,
            CompressionLevelSerde::Light => CompressionLevel::Light,
            CompressionLevelSerde::Medium => CompressionLevel::Medium,
            CompressionLevelSerde::High => CompressionLevel::High,
        }
    }
} 