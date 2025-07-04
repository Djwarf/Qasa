//! Hybrid Classical/Post-Quantum Cryptographic Modes
//! 
//! This module provides implementations of hybrid cryptographic schemes that combine
//! classical and post-quantum algorithms for enhanced security. These hybrid modes
//! provide protection against both classical and quantum adversaries, ensuring a smooth
//! transition to post-quantum cryptography while maintaining compatibility with
//! existing systems.

pub mod hybrid_kem;
pub mod hybrid_signature;
pub mod hybrid_encryption;
pub mod composite;
mod tests;

pub use hybrid_kem::{
    HybridKemKeyPair,
    HybridKemPublicKey,
    HybridKemVariant,
    HybridKemCiphertext
};

pub use hybrid_signature::{
    HybridSignatureKeyPair,
    HybridSignaturePublicKey,
    HybridSignatureVariant,
    HybridSignature
};

pub use hybrid_encryption::{
    encrypt_hybrid,
    decrypt_hybrid,
    HybridEncryptionParameters
};

pub use composite::{
    CompositeKeyPair,
    CompositePublicKey,
    CompositeScheme
}; 