/*!
 * QaSa Cryptography Module
 * 
 * This module implements post-quantum cryptographic primitives for the QaSa
 * secure chat application, with a focus on providing quantum-resistant security.
 */

/// CRYSTALS-Kyber implementation for key encapsulation
pub mod kyber;

/// CRYSTALS-Dilithium implementation for digital signatures
pub mod dilithium;

/// AES-GCM implementation for symmetric encryption
pub mod aes;

/// Key management system for storing and loading keys
pub mod key_management;

/// Common error types for the cryptography module
pub mod error;

/// Utilities for cryptographic operations
pub mod utils;

/// Foreign Function Interface (FFI) for integration with other languages
pub mod ffi;

// Re-export main types for convenience
pub use error::CryptoError;
pub use kyber::KyberKeyPair;
pub use dilithium::DilithiumKeyPair;

/// Initialize the cryptography module.
/// This function should be called before using any cryptographic functions.
/// It performs any necessary setup for the underlying cryptographic libraries.
/// 
/// # Returns
/// 
/// `Ok(())` if initialization is successful, or an error if initialization fails
pub fn init() -> Result<(), CryptoError> {
    // Currently, no special initialization is needed
    // This function is here for future-proofing if initialization is needed later
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
