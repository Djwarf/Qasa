//! Hybrid Digital Signature Scheme
//!
//! This module provides an implementation of hybrid signature schemes that combine
//! classical and post-quantum algorithms for enhanced security.

use std::fmt;
use std::fmt::Display;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, CryptoResult};
use crate::dilithium::{DilithiumKeyPair, DilithiumPublicKey, DilithiumVariant};
use crate::sphincsplus::{SphincsKeyPair, SphincsPublicKey, SphincsVariant};
use crate::secure_memory::SecureBytes;
use crate::utils;

/// Classical signature algorithms for hybrid use
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClassicalSignatureAlgorithm {
    /// ECDSA with P-256
    EcdsaP256,
    /// Ed25519
    Ed25519,
    /// RSA-2048
    Rsa2048,
    /// RSA-3072
    Rsa3072,
}

/// Post-quantum signature algorithms for hybrid use
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PostQuantumSignatureAlgorithm {
    /// CRYSTALS-Dilithium
    Dilithium(DilithiumVariant),
    /// SPHINCS+
    Sphincs(SphincsVariant),
}

/// Hybrid signature variant combining a classical and post-quantum algorithm
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HybridSignatureVariant {
    /// Classical algorithm component
    pub classical: ClassicalSignatureAlgorithm,
    /// Post-quantum algorithm component
    pub post_quantum: PostQuantumSignatureAlgorithm,
}

/// Hybrid signature key pair for signing
#[derive(Debug)]
pub struct HybridSignatureKeyPair {
    /// Classical key pair component
    pub classical_key: Vec<u8>,
    /// Post-quantum key pair component
    pub post_quantum_key: Vec<u8>,
    /// The hybrid algorithm variant
    pub algorithm: HybridSignatureVariant,
}

/// Hybrid signature public key for verification
pub struct HybridSignaturePublicKey {
    /// Classical public key component
    pub classical_key: Vec<u8>,
    /// Post-quantum public key component
    pub post_quantum_key: Vec<u8>,
    /// The hybrid algorithm variant
    pub algorithm: HybridSignatureVariant,
}

/// Hybrid signature containing both classical and post-quantum components
#[derive(Debug)]
pub struct HybridSignature {
    /// Classical signature component
    pub classical_signature: Vec<u8>,
    /// Post-quantum signature component
    pub post_quantum_signature: Vec<u8>,
    /// The hybrid algorithm variant
    pub algorithm: HybridSignatureVariant,
}

impl Display for ClassicalSignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClassicalSignatureAlgorithm::EcdsaP256 => write!(f, "ECDSA-P256"),
            ClassicalSignatureAlgorithm::Ed25519 => write!(f, "Ed25519"),
            ClassicalSignatureAlgorithm::Rsa2048 => write!(f, "RSA-2048"),
            ClassicalSignatureAlgorithm::Rsa3072 => write!(f, "RSA-3072"),
        }
    }
}

impl Display for PostQuantumSignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PostQuantumSignatureAlgorithm::Dilithium(variant) => write!(f, "Dilithium-{}", variant),
            PostQuantumSignatureAlgorithm::Sphincs(variant) => write!(f, "SPHINCS+-{}", variant),
        }
    }
}

impl Display for HybridSignatureVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.classical, self.post_quantum)
    }
}

impl Zeroize for HybridSignatureKeyPair {
    fn zeroize(&mut self) {
        self.classical_key.zeroize();
        self.post_quantum_key.zeroize();
    }
}

impl Drop for HybridSignatureKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
} 