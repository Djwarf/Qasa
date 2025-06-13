/*!
 * CRYSTALS-Kyber implementation for quantum-resistant key encapsulation
 *
 * This module implements the CRYSTALS-Kyber algorithm for key encapsulation
 * as standardized by NIST for post-quantum cryptography.
 */

mod kyber;
pub mod lean;

pub use kyber::{KyberKeyPair, KyberPublicKey, KyberVariant};

#[cfg(feature = "lean")]
pub use lean::{KyberKeyPair as LeanKyberKeyPair, KyberPublicKey as LeanKyberPublicKey};

// Re-export KyberVariant with Serialize and Deserialize traits
use serde::{Serialize, Deserialize};

// Add Serialize and Deserialize traits to KyberVariant
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KyberVariantSerde {
    Kyber512,
    Kyber768,
    Kyber1024,
}

impl From<KyberVariant> for KyberVariantSerde {
    fn from(variant: KyberVariant) -> Self {
        match variant {
            KyberVariant::Kyber512 => KyberVariantSerde::Kyber512,
            KyberVariant::Kyber768 => KyberVariantSerde::Kyber768,
            KyberVariant::Kyber1024 => KyberVariantSerde::Kyber1024,
        }
    }
}

impl From<KyberVariantSerde> for KyberVariant {
    fn from(variant: KyberVariantSerde) -> Self {
        match variant {
            KyberVariantSerde::Kyber512 => KyberVariant::Kyber512,
            KyberVariantSerde::Kyber768 => KyberVariant::Kyber768,
            KyberVariantSerde::Kyber1024 => KyberVariant::Kyber1024,
        }
    }
}

#[cfg(test)]
mod tests;
