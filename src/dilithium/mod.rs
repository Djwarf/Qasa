/*!
 * CRYSTALS-Dilithium implementation for quantum-resistant digital signatures
 *
 * This module implements the CRYSTALS-Dilithium algorithm for digital signatures
 * as standardised by NIST for post-quantum cryptography.
 */

mod dilithium;
mod optimizations;
mod compression;

pub use dilithium::*;
pub use optimizations::LeanDilithium;
pub use compression::{
    CompressedSignature,
    CompressionLevel,
    compress_signature,
    decompress_signature,
};

#[cfg(test)]
mod tests;

// Re-export with Serialize and Deserialize traits
use serde::{Serialize, Deserialize};

// Add Serialize and Deserialize traits to DilithiumVariant
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DilithiumVariantSerde {
    Dilithium2,
    Dilithium3,
    Dilithium5,
}

impl From<DilithiumVariant> for DilithiumVariantSerde {
    fn from(variant: DilithiumVariant) -> Self {
        match variant {
            DilithiumVariant::Dilithium2 => DilithiumVariantSerde::Dilithium2,
            DilithiumVariant::Dilithium3 => DilithiumVariantSerde::Dilithium3,
            DilithiumVariant::Dilithium5 => DilithiumVariantSerde::Dilithium5,
        }
    }
}

impl From<DilithiumVariantSerde> for DilithiumVariant {
    fn from(variant: DilithiumVariantSerde) -> Self {
        match variant {
            DilithiumVariantSerde::Dilithium2 => DilithiumVariant::Dilithium2,
            DilithiumVariantSerde::Dilithium3 => DilithiumVariant::Dilithium3,
            DilithiumVariantSerde::Dilithium5 => DilithiumVariant::Dilithium5,
        }
    }
}

// Add Serialize and Deserialize traits to CompressionLevel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
