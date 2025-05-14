use std::io;
use thiserror::Error;

/// Error types for cryptographic operations
///
/// This enum provides a comprehensive set of error types that can occur
/// during cryptographic operations in the QaSa application. Each variant
/// includes a descriptive message to help with debugging and error handling.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Error from the OQS library
    /// 
    /// This error occurs when there's an issue with the underlying Open Quantum Safe library,
    /// which provides the post-quantum cryptographic algorithms.
    #[error("OQS error: {0}")]
    OqsError(String),

    /// Error during key generation
    /// 
    /// This error occurs when there's a problem generating cryptographic keys,
    /// such as insufficient entropy or algorithm-specific issues.
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    /// Error during encapsulation
    /// 
    /// This error occurs when there's a problem during the key encapsulation
    /// process, which is used in key exchange mechanisms like Kyber.
    #[error("Encapsulation error: {0}")]
    EncapsulationError(String),

    /// Error during decapsulation
    /// 
    /// This error occurs when there's a problem recovering the shared secret
    /// during the key decapsulation process, potentially due to corrupt ciphertext.
    #[error("Decapsulation error: {0}")]
    DecapsulationError(String),

    /// Error during signature generation
    /// 
    /// This error occurs when there's a problem generating a digital signature,
    /// which can happen due to key issues or algorithm failures.
    #[error("Signature generation error: {0}")]
    SignatureGenerationError(String),

    /// Error during signature verification
    /// 
    /// This error occurs when there's a problem verifying a digital signature,
    /// which is different from a signature failing verification (which would return false).
    #[error("Signature verification error: {0}")]
    SignatureVerificationError(String),

    /// Error during encryption
    /// 
    /// This error occurs when there's a problem during the encryption process,
    /// such as issues with the key, nonce, or plaintext.
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Error during decryption
    /// 
    /// This error occurs when there's a problem during the decryption process,
    /// such as authentication failures, corrupt ciphertext, or wrong key.
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Error during serialization/deserialization
    /// 
    /// This error occurs when there's a problem converting data structures to bytes
    /// or reconstructing data structures from bytes.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Error related to key management
    /// 
    /// This error occurs during key storage, loading, rotation, or other
    /// key management operations.
    #[error("Key management error: {0}")]
    KeyManagementError(String),

    /// Error during key verification
    /// 
    /// This error occurs when there's a problem verifying the integrity or
    /// correctness of a cryptographic key.
    #[error("Key verification error: {0}")]
    KeyVerificationError(String),

    /// IO Error
    /// 
    /// This error occurs when there's a problem with file or network I/O operations,
    /// and wraps the standard Rust I/O error.
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    /// Invalid parameter error
    /// 
    /// This error occurs when a function is called with invalid parameters,
    /// such as incorrect key sizes or incompatible algorithm choices.
    #[error("Invalid parameter: {0}")]
    InvalidParameterError(String),

    /// Error during random number generation
    /// 
    /// This error occurs when there's a problem generating cryptographically
    /// secure random numbers, which are essential for many crypto operations.
    #[error("Random number generation error: {0}")]
    RandomGenerationError(String),
    
    /// Error due to invalid password
    /// 
    /// This error occurs when an incorrect password is provided during
    /// authentication or key derivation operations.
    #[error("Invalid password: {0}")]
    InvalidPasswordError(String),

    /// Feature not implemented yet
    /// 
    /// This error indicates that the requested feature or operation
    /// is planned but not yet implemented in the current version.
    #[error("Feature not implemented yet")]
    NotImplemented,
}
