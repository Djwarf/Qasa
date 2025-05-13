use std::io;
use thiserror::Error;

/// Error types for cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Error from the OQS library
    #[error("OQS error: {0}")]
    OqsError(String),

    /// Error during key generation
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    /// Error during encapsulation
    #[error("Encapsulation error: {0}")]
    EncapsulationError(String),

    /// Error during decapsulation
    #[error("Decapsulation error: {0}")]
    DecapsulationError(String),

    /// Error during signature generation
    #[error("Signature generation error: {0}")]
    SignatureGenerationError(String),

    /// Error during signature verification
    #[error("Signature verification error: {0}")]
    SignatureVerificationError(String),

    /// Error during encryption
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Error during decryption
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Error during serialization/deserialization
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Error related to key management
    #[error("Key management error: {0}")]
    KeyManagementError(String),

    /// Error during key verification
    #[error("Key verification error: {0}")]
    KeyVerificationError(String),

    /// IO Error
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    /// Invalid parameter error
    #[error("Invalid parameter: {0}")]
    InvalidParameterError(String),

    /// Error during random number generation
    #[error("Random number generation error: {0}")]
    RandomGenerationError(String),
    
    /// Error due to invalid password
    #[error("Invalid password: {0}")]
    InvalidPasswordError(String),

    /// Feature not implemented yet
    #[error("Feature not implemented yet")]
    NotImplemented,
}
