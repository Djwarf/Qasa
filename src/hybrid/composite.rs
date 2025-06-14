//! Composite Cryptographic Schemes
//!
//! This module provides implementations of composite cryptographic schemes that combine
//! multiple algorithms for enhanced security.

use std::fmt;
use std::fmt::Display;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, CryptoResult};
use crate::secure_memory::SecureBytes;
use crate::utils;

/// Types of cryptographic schemes that can be composed
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SchemeType {
    /// Key encapsulation mechanism
    Kem,
    /// Digital signature scheme
    Signature,
    /// Authenticated encryption scheme
    AuthenticatedEncryption,
}

/// A component in a composite scheme
#[derive(Debug, Clone)]
pub struct SchemeComponent {
    /// Name of the algorithm
    pub name: String,
    /// Type of scheme
    pub scheme_type: SchemeType,
    /// Security level in bits
    pub security_level: u32,
    /// Whether the algorithm is post-quantum secure
    pub post_quantum: bool,
}

/// A composite cryptographic scheme combining multiple algorithms
#[derive(Debug, Clone)]
pub struct CompositeScheme {
    /// Name of the composite scheme
    pub name: String,
    /// Components that make up the scheme
    pub components: Vec<SchemeComponent>,
    /// Composition method
    pub composition_method: CompositionMethod,
}

/// Method used to combine multiple algorithms
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompositionMethod {
    /// Sequential composition (each algorithm is applied in sequence)
    Sequential,
    /// Parallel composition (all algorithms are applied in parallel)
    Parallel,
    /// XOR composition (shared secrets are XORed together)
    Xor,
    /// Concatenation composition (outputs are concatenated)
    Concatenation,
}

/// A key pair for a composite scheme
#[derive(Debug)]
pub struct CompositeKeyPair {
    /// Key data for each component
    pub component_keys: Vec<Vec<u8>>,
    /// The composite scheme
    pub scheme: CompositeScheme,
}

/// A public key for a composite scheme
pub struct CompositePublicKey {
    /// Key data for each component
    pub component_keys: Vec<Vec<u8>>,
    /// The composite scheme
    pub scheme: CompositeScheme,
}

impl Display for SchemeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemeType::Kem => write!(f, "KEM"),
            SchemeType::Signature => write!(f, "Signature"),
            SchemeType::AuthenticatedEncryption => write!(f, "AuthenticatedEncryption"),
        }
    }
}

impl Display for CompositionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompositionMethod::Sequential => write!(f, "Sequential"),
            CompositionMethod::Parallel => write!(f, "Parallel"),
            CompositionMethod::Xor => write!(f, "XOR"),
            CompositionMethod::Concatenation => write!(f, "Concatenation"),
        }
    }
}

impl Display for CompositeScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (", self.name)?;
        for (i, component) in self.components.iter().enumerate() {
            if i > 0 {
                write!(f, " + ")?;
            }
            write!(f, "{}", component.name)?;
        }
        write!(f, " using {} composition)", self.composition_method)
    }
}

impl Display for SchemeComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}, security: {} bits, PQ: {})",
            self.name,
            self.scheme_type,
            self.security_level,
            if self.post_quantum { "Yes" } else { "No" }
        )
    }
}

impl Zeroize for CompositeKeyPair {
    fn zeroize(&mut self) {
        for key in &mut self.component_keys {
            key.zeroize();
        }
    }
}

impl Drop for CompositeKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
} 