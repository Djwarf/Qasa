//! BIKE post-quantum key encapsulation mechanism
//! 
//! BIKE (Bit-flipping Key Encapsulation) is a code-based key encapsulation mechanism
//! that was submitted to the NIST post-quantum cryptography standardization process.
//! 
//! This module provides an implementation of BIKE with various parameter sets
//! for different security levels and performance characteristics.

mod bike;
mod parameters;
mod tests;

pub use bike::{
    BikeKeyPair, 
    BikePublicKey, 
    BikeVariant,
    CompressedCiphertext,
    CompressionLevel
};

/// Serializable version of BikeVariant for storage
#[derive(serde::Serialize, serde::Deserialize)]
pub enum BikeVariantSerde {
    /// BIKE-1 Level 1 (128-bit security)
    Bike1Level1,
    /// BIKE-1 Level 3 (192-bit security)
    Bike1Level3,
    /// BIKE-1 Level 5 (256-bit security)
    Bike1Level5,
}

impl From<BikeVariant> for BikeVariantSerde {
    fn from(variant: BikeVariant) -> Self {
        match variant {
            BikeVariant::Bike1Level1 => BikeVariantSerde::Bike1Level1,
            BikeVariant::Bike1Level3 => BikeVariantSerde::Bike1Level3,
            BikeVariant::Bike1Level5 => BikeVariantSerde::Bike1Level5,
        }
    }
}

impl From<BikeVariantSerde> for BikeVariant {
    fn from(variant: BikeVariantSerde) -> Self {
        match variant {
            BikeVariantSerde::Bike1Level1 => BikeVariant::Bike1Level1,
            BikeVariantSerde::Bike1Level3 => BikeVariant::Bike1Level3,
            BikeVariantSerde::Bike1Level5 => BikeVariant::Bike1Level5,
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