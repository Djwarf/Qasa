//! Hybrid Key Encapsulation Mechanism (KEM)
//!
//! This module provides an implementation of hybrid KEMs that combine
//! classical and post-quantum algorithms for enhanced security.

use std::fmt;
use std::fmt::Display;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, CryptoResult};
use crate::kyber::{KyberKeyPair, KyberPublicKey, KyberVariant};
use crate::bike::{BikeKeyPair, BikePublicKey, BikeVariant};
use crate::secure_memory::SecureBytes;
use crate::utils;

/// Classical KEM algorithms for hybrid use
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClassicalKemAlgorithm {
    /// ECDH with X25519
    X25519,
    /// ECDH with P-256
    P256,
    /// RSA-2048
    Rsa2048,
    /// RSA-3072
    Rsa3072,
}

/// Post-quantum KEM algorithms for hybrid use
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PostQuantumKemAlgorithm {
    /// CRYSTALS-Kyber
    Kyber(KyberVariant),
    /// BIKE
    Bike(BikeVariant),
}

/// Hybrid KEM variant combining a classical and post-quantum algorithm
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HybridKemVariant {
    /// Classical algorithm component
    pub classical: ClassicalKemAlgorithm,
    /// Post-quantum algorithm component
    pub post_quantum: PostQuantumKemAlgorithm,
}

/// Hybrid KEM key pair for encapsulation and decapsulation
#[derive(Debug)]
pub struct HybridKemKeyPair {
    /// Classical key pair component
    pub classical_key: Vec<u8>,
    /// Post-quantum key pair component
    pub post_quantum_key: Vec<u8>,
    /// The hybrid algorithm variant
    pub algorithm: HybridKemVariant,
}

/// Hybrid KEM public key for encapsulation
pub struct HybridKemPublicKey {
    /// Classical public key component
    pub classical_key: Vec<u8>,
    /// Post-quantum public key component
    pub post_quantum_key: Vec<u8>,
    /// The hybrid algorithm variant
    pub algorithm: HybridKemVariant,
}

/// Hybrid KEM ciphertext containing both classical and post-quantum components
#[derive(Debug)]
pub struct HybridKemCiphertext {
    /// Classical ciphertext component
    pub classical_ciphertext: Vec<u8>,
    /// Post-quantum ciphertext component
    pub post_quantum_ciphertext: Vec<u8>,
    /// The hybrid algorithm variant
    pub algorithm: HybridKemVariant,
}

impl Display for ClassicalKemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClassicalKemAlgorithm::X25519 => write!(f, "X25519"),
            ClassicalKemAlgorithm::P256 => write!(f, "P-256"),
            ClassicalKemAlgorithm::Rsa2048 => write!(f, "RSA-2048"),
            ClassicalKemAlgorithm::Rsa3072 => write!(f, "RSA-3072"),
        }
    }
}

impl Display for PostQuantumKemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PostQuantumKemAlgorithm::Kyber(variant) => write!(f, "Kyber-{}", variant),
            PostQuantumKemAlgorithm::Bike(variant) => write!(f, "BIKE-{}", variant),
        }
    }
}

impl Display for HybridKemVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.classical, self.post_quantum)
    }
}

impl Zeroize for HybridKemKeyPair {
    fn zeroize(&mut self) {
        self.classical_key.zeroize();
        self.post_quantum_key.zeroize();
    }
}

impl Drop for HybridKemKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}
