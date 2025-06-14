/*!
 * QaSa Cryptography Module
 *
 * This module implements post-quantum cryptographic primitives for the QaSa
 * quantum-safe cryptographic operations, with a focus on providing quantum-resistant security.
 *
 * The main cryptographic algorithms used are:
 *
 * - CRYSTALS-Kyber for key encapsulation (KEM)
 * - CRYSTALS-Dilithium for digital signatures
 * - AES-GCM for symmetric encryption
 *
 * These are combined to provide a comprehensive encryption system that is
 * resistant to attacks from both classical and quantum computers.
 */

/// CRYSTALS-Kyber implementation for key encapsulation
pub mod kyber;

/// CRYSTALS-Dilithium implementation for digital signatures
pub mod dilithium;

/// SPHINCS+ implementation for digital signatures
pub mod sphincsplus;

/// BIKE implementation for key encapsulation
pub mod bike;

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

/// Secure memory handling utilities
pub mod secure_memory;

/// SIMD acceleration framework
pub mod simd;

/// High-level protocol implementations
pub mod protocols;

/// Security framework including constant-time verification
pub mod security;

/// High-level user-friendly API
pub mod simple;

// Re-export main types for convenience
pub use dilithium::DilithiumKeyPair;
pub use dilithium::DilithiumPublicKey;
pub use dilithium::DilithiumVariant;
pub use sphincsplus::SphincsKeyPair;
pub use sphincsplus::SphincsPublicKey;
pub use sphincsplus::SphincsVariant;
pub use sphincsplus::CompressionLevel as SphincsCompressionLevel;
pub use sphincsplus::CompressedSignature as SphincsCompressedSignature;
pub use bike::BikeKeyPair;
pub use bike::BikePublicKey;
pub use bike::BikeVariant;
pub use bike::CompressionLevel as BikeCompressionLevel;
pub use bike::CompressedCiphertext as BikeCompressedCiphertext;
pub use error::{CryptoError, CryptoResult};
pub use kyber::KyberKeyPair;
pub use kyber::KyberPublicKey;
pub use kyber::KyberVariant;

/// Initialize the cryptography module.
///
/// This function should be called before using any cryptographic functions.
/// It performs any necessary setup for the underlying cryptographic libraries.
///
/// While currently no special initialization is needed, this function provides
/// a consistent API that can accommodate future initialization requirements
/// for cryptographic backends.
///
/// # Returns
///
/// `Ok(())` if initialization is successful, or an error if initialization fails
///
/// # Example
///
/// ```
/// use qasa::prelude::*;
///
/// fn main() -> Result<(), CryptoError> {
///     // Initialize the cryptography module
///     init()?;
///     
///     // Now safe to use cryptographic functions
///     // ...
///     
///     Ok(())
/// }
/// ```
pub fn init() -> Result<(), CryptoError> {
    // Currently, no special initialization is needed, but this function exists
    // to provide a consistent API that can accommodate future requirements
    Ok(())
}

/// Provides a simplified interface to the most commonly used cryptographic operations.
///
/// This aims to make the library easier to use with reasonable defaults.
pub mod prelude {
    pub use crate::decrypt_and_verify_message;
    pub use crate::decrypt_message;
    pub use crate::encrypt_and_sign_message;
    pub use crate::encrypt_message;
    pub use crate::init;
    pub use crate::key_management::change_password;
    pub use crate::key_management::delete_key;
    pub use crate::key_management::derive_key_from_password;
    pub use crate::key_management::export_key;
    pub use crate::key_management::import_key;
    pub use crate::key_management::list_keys;
    pub use crate::key_management::load_dilithium_keypair;
    pub use crate::key_management::load_kyber_keypair;
    pub use crate::key_management::password::high_security_params;
    pub use crate::key_management::rotate_dilithium_keypair;
    pub use crate::key_management::rotate_kyber_keypair;
    pub use crate::key_management::store_dilithium_keypair;
    pub use crate::key_management::store_kyber_keypair;
    pub use crate::key_management::verify_password;
    pub use crate::key_management::DerivedKey;
    pub use crate::key_management::KeyAgeSummary;
    pub use crate::key_management::KeyDerivationParams;
    pub use crate::key_management::KeyRotationMetadata;
    pub use crate::key_management::RotationPolicy;
    pub use crate::secure_memory::with_secure_scope;
    pub use crate::secure_memory::SecureBuffer;
    pub use crate::secure_memory::SecureBytes;
    pub use crate::secure_memory::LockedMemory;
    pub use crate::secure_memory::LockedBuffer;
    pub use crate::secure_memory::CanaryBuffer;
    pub use crate::secure_memory::DEFAULT_CANARY_PATTERN;
    pub use crate::sign_message;
    pub use crate::verify_message;
    pub use crate::CryptoError;
    pub use crate::DilithiumKeyPair;
    pub use crate::DilithiumPublicKey;
    pub use crate::DilithiumVariant;
    pub use crate::SphincsKeyPair;
    pub use crate::SphincsPublicKey;
    pub use crate::SphincsVariant;
    pub use crate::SphincsCompressionLevel;
    pub use crate::SphincsCompressedSignature;
    pub use crate::BikeKeyPair;
    pub use crate::BikePublicKey;
    pub use crate::BikeVariant;
    pub use crate::BikeCompressionLevel;
    pub use crate::BikeCompressedCiphertext;
    pub use crate::KyberKeyPair;
    pub use crate::KyberPublicKey;
    pub use crate::KyberVariant;

    /// Creates an end-to-end encrypted message ready for sending
    ///
    /// This is a higher-level function that combines the necessary cryptographic
    /// operations to encrypt and sign a message for secure transmission.
    ///
    /// # Arguments
    ///
    /// * `message` - The plaintext message to encrypt
    /// * `recipient_public_key` - The recipient's Kyber public key for encryption
    /// * `sender_signing_key` - The sender's Dilithium key pair for signing
    ///
    /// # Returns
    ///
    /// The encrypted and signed message package, or an error
    ///
    /// # Security Properties
    ///
    /// 1. Uses post-quantum key encapsulation for forward secrecy
    /// 2. Applies authenticated encryption for message confidentiality and integrity
    /// 3. Signs the encrypted message to provide sender authentication
    /// 4. Protects against both classical and quantum attacks
    pub fn create_secure_message(
        message: &[u8],
        recipient_public_key: &crate::kyber::KyberPublicKey,
        sender_signing_key: &crate::dilithium::DilithiumKeyPair,
    ) -> Result<Vec<u8>, crate::CryptoError> {
        // Perform key encapsulation to get a shared secret
        let (ciphertext, shared_secret) = recipient_public_key.encapsulate()?;

        // Encrypt the message with the shared secret
        let (encrypted_message, nonce) = crate::aes::encrypt(message, &shared_secret, None)?;

        // Create a message package containing all necessary components
        let message_package = MessagePackage {
            kyber_ciphertext: ciphertext,
            encrypted_message,
            nonce,
        };

        // Serialize the message package
        let serialized = bincode::serialize(&message_package)
            .map_err(|e| crate::CryptoError::SerializationError(e.to_string()))?;

        // Sign the serialized package
        let signature = sender_signing_key.sign(&serialized)?;

        // Create the final signed package
        let signed_package = SignedPackage {
            message_data: serialized,
            signature,
        };

        // Serialize the final package
        bincode::serialize(&signed_package)
            .map_err(|e| crate::CryptoError::SerializationError(e.to_string()))
    }

    /// Opens an end-to-end encrypted message
    ///
    /// This is a higher-level function that combines the necessary cryptographic
    /// operations to verify and decrypt a received secure message.
    ///
    /// # Arguments
    ///
    /// * `encrypted_message` - The encrypted message package
    /// * `recipient_private_key` - The recipient's Kyber key pair for decryption
    /// * `sender_verify_key` - The sender's Dilithium public key for verification
    ///
    /// # Returns
    ///
    /// The decrypted plaintext message, or an error
    ///
    /// # Security Properties
    ///
    /// 1. Verifies the sender's signature before attempting decryption
    /// 2. Fails immediately if signature verification fails, preventing oracle attacks
    /// 3. Uses post-quantum secure algorithms for all cryptographic operations
    /// 4. Provides authentication, integrity and confidentiality
    pub fn open_secure_message(
        encrypted_message: &[u8],
        recipient_private_key: &crate::kyber::KyberKeyPair,
        sender_verify_key: &crate::dilithium::DilithiumPublicKey,
    ) -> Result<Vec<u8>, crate::CryptoError> {
        // Deserialize the signed package
        let signed_package: SignedPackage =
            bincode::deserialize(encrypted_message).map_err(|e| {
                crate::CryptoError::SerializationError(format!(
                    "Failed to deserialize message: {}",
                    e
                ))
            })?;

        // Verify the signature
        let verification_result = crate::dilithium::DilithiumKeyPair::verify_with_public_key(
            sender_verify_key.algorithm,
            &sender_verify_key.public_key,
            &signed_package.message_data,
            &signed_package.signature,
        )?;

        if !verification_result {
            return Err(crate::CryptoError::dilithium_error(
                "signature_verification",
                "Message signature verification failed",
                crate::error::error_codes::DILITHIUM_VERIFICATION_FAILED,
            ));
        }

        // Deserialize the verified message package
        let message_package: MessagePackage = bincode::deserialize(&signed_package.message_data)
            .map_err(|e| {
                crate::CryptoError::SerializationError(format!(
                    "Failed to deserialize message package: {}",
                    e
                ))
            })?;

        // Decapsulate the shared secret
        let shared_secret = recipient_private_key.decapsulate(&message_package.kyber_ciphertext)?;

        // Decrypt the message
        let plaintext = crate::aes::decrypt(
            &message_package.encrypted_message,
            &shared_secret,
            &message_package.nonce,
            None,
        )?;

        Ok(plaintext)
    }

    // Internal structures for message packaging

    #[derive(serde::Serialize, serde::Deserialize)]
    struct MessagePackage {
        kyber_ciphertext: Vec<u8>,
        encrypted_message: Vec<u8>,
        nonce: Vec<u8>,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct SignedPackage {
        message_data: Vec<u8>,
        signature: Vec<u8>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        assert!(init().is_ok());
    }

    #[test]
    fn test_prelude_secure_messaging() {
        use prelude::*;

        // Initialize
        init().unwrap();

        // Generate keys for Mary and Elena
        let mary_enc_keys = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        let mary_sig_keys = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();

        let elena_enc_keys = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        let elena_sig_keys = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();

        // Extract public keys
        let _mary_enc_pub = mary_enc_keys.public_key();
        let mary_sig_pub = mary_sig_keys.public_key();

        let elena_enc_pub = elena_enc_keys.public_key();
        let _elena_sig_pub = elena_sig_keys.public_key();

        // Test message from Mary to Elena
        let message = b"Hello Elena, this is a secure message from Mary!";

        // Mary creates a secure message for Elena
        let secure_msg = create_secure_message(message, &elena_enc_pub, &mary_sig_keys).unwrap();

        // Elena receives and opens the message
        let decrypted = open_secure_message(&secure_msg, &elena_enc_keys, &mary_sig_pub).unwrap();

        // Verify the message content
        assert_eq!(decrypted, message);
    }
}

/// Encrypt a message for a specific recipient using hybrid encryption
///
/// This function combines Kyber KEM (Key Encapsulation Mechanism) for key exchange
/// and AES-GCM for symmetric encryption to provide post-quantum secure message encryption.
/// First, a shared secret is established using the recipient's public key, then
/// the message is encrypted using AES-GCM with that shared secret.
///
/// # Arguments
///
/// * `message` - The plaintext message to encrypt
/// * `recipient_public_key` - The recipient's Kyber public key
///
/// # Returns
///
/// A tuple containing:
/// * `encrypted_message` - The AES-encrypted message
/// * `encapsulated_key` - The Kyber-encapsulated key that must be sent alongside the message
/// * `nonce` - The nonce used for AES-GCM encryption
///
/// # Errors
///
/// Returns an error if key encapsulation fails or if encryption fails
///
/// # Security Properties
///
/// 1. Post-quantum secure key encapsulation using Kyber
/// 2. Authenticated encryption via AES-GCM
/// 3. Unique key for each message (forward secrecy)
pub fn encrypt_message(
    message: &[u8],
    recipient_public_key: &crate::kyber::KyberPublicKey,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), CryptoError> {
    // Perform key encapsulation
    let (encapsulated_key, shared_secret) = recipient_public_key.encapsulate()?;

    // Encrypt the message with the shared secret
    let (encrypted_message, nonce) = aes::encrypt(message, &shared_secret, None)?;

    Ok((encrypted_message, encapsulated_key, nonce))
}

/// Decrypt a message received from a sender using hybrid decryption
///
/// This function recovers the shared secret from the encapsulated key using the
/// recipient's private key, then uses that shared secret to decrypt the message
/// with AES-GCM.
///
/// # Arguments
///
/// * `encrypted_message` - The AES-encrypted message
/// * `encapsulated_key` - The Kyber-encapsulated key received from the sender
/// * `nonce` - The nonce used for AES-GCM encryption
/// * `my_keypair` - The recipient's Kyber key pair containing the private key
///
/// # Returns
///
/// The decrypted plaintext message if successful
///
/// # Errors
///
/// Returns an error if key decapsulation fails or if decryption fails
/// (which can happen if the message was tampered with or corrupted)
///
/// # Security Properties
///
/// 1. Authenticated decryption that verifies message integrity and authenticity
/// 2. Post-quantum secure key recovery
pub fn decrypt_message(
    encrypted_message: &[u8],
    encapsulated_key: &[u8],
    nonce: &[u8],
    my_keypair: &crate::kyber::KyberKeyPair,
) -> Result<Vec<u8>, CryptoError> {
    // Recover the shared secret
    let shared_secret = my_keypair.decapsulate(encapsulated_key)?;

    // Decrypt the message with the shared secret
    let plaintext = aes::decrypt(encrypted_message, &shared_secret, nonce, None)?;

    Ok(plaintext)
}

/// Sign a message using post-quantum digital signature
///
/// This function creates a Dilithium digital signature for a message using the
/// provided private key. The signature can later be verified to ensure the message
/// came from the owner of the private key and was not modified.
///
/// # Arguments
///
/// * `message` - The message to sign
/// * `signing_key` - The Dilithium key pair containing the private key
///
/// # Returns
///
/// The Dilithium signature for the message
///
/// # Errors
///
/// Returns an error if signature generation fails
///
/// # Security Properties
///
/// 1. Post-quantum secure digital signature using Dilithium
/// 2. Provides authenticity and integrity verification
/// 3. Non-repudiation (signer cannot deny having signed the message)
pub fn sign_message(
    message: &[u8],
    signing_key: &crate::dilithium::DilithiumKeyPair,
) -> Result<Vec<u8>, CryptoError> {
    signing_key.sign(message)
}

/// Verify a signed message using post-quantum digital signature
///
/// This function verifies a Dilithium digital signature against a message and
/// public key to confirm that the message was signed by the owner of the
/// corresponding private key and has not been modified.
///
/// # Arguments
///
/// * `message` - The message to verify
/// * `signature` - The signature to verify
/// * `sender_verify_key` - The sender's Dilithium public key
///
/// # Returns
///
/// * `Ok(true)` if the signature is valid for the message and public key
/// * `Ok(false)` if the signature is invalid
/// * `Err(CryptoError)` if an error occurs during verification
///
/// # Security Properties
///
/// 1. Post-quantum secure signature verification using Dilithium
/// 2. Verifies both authenticity (who created the message) and integrity (message not modified)
pub fn verify_message(
    message: &[u8],
    signature: &[u8],
    sender_verify_key: &crate::dilithium::DilithiumPublicKey,
) -> Result<bool, CryptoError> {
    sender_verify_key.verify(message, signature)
}

/// Encrypt and sign a message in one operation for secure communication
///
/// This function combines encryption and signing to provide a complete secure
/// messaging solution with confidentiality, integrity, and authenticity. It first
/// encrypts the message for the recipient, then signs the encrypted package to
/// prove the sender's identity.
///
/// # Arguments
///
/// * `message` - The plaintext message to encrypt and sign
/// * `recipient_public_key` - The recipient's Kyber public key for encryption
/// * `signing_key` - The sender's Dilithium key pair for signing
///
/// # Returns
///
/// A tuple containing:
/// * `encrypted_message` - The AES-encrypted message
/// * `encapsulated_key` - The Kyber-encapsulated key
/// * `nonce` - The nonce used for AES-GCM encryption
/// * `signature` - The Dilithium signature of the combined encrypted data
///
/// # Errors
///
/// Returns an error if encryption or signing fails
///
/// # Security Properties
///
/// 1. Combines confidentiality (encryption) with authenticity and integrity (signing)
/// 2. Signs the encrypted message rather than the plaintext, preventing signature-based oracles
/// 3. Uses post-quantum secure algorithms for all cryptographic operations
pub fn encrypt_and_sign_message(
    message: &[u8],
    recipient_public_key: &crate::kyber::KyberPublicKey,
    signing_key: &crate::dilithium::DilithiumKeyPair,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), CryptoError> {
    // Encrypt the message
    let (encrypted_message, encapsulated_key, nonce) =
        encrypt_message(message, recipient_public_key)?;

    // Sign the encrypted message + encapsulated key (to prevent tampering)
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(&encrypted_message);
    to_sign.extend_from_slice(&encapsulated_key);
    to_sign.extend_from_slice(&nonce);

    let signature = sign_message(&to_sign, signing_key)?;

    Ok((encrypted_message, encapsulated_key, nonce, signature))
}

/// Decrypt and verify a signed and encrypted message
///
/// This function verifies the signature on an encrypted message package and, if valid,
/// decrypts the message. This ensures the message came from the expected sender and
/// has not been tampered with before decryption.
///
/// # Arguments
///
/// * `encrypted_message` - The AES-encrypted message
/// * `encapsulated_key` - The Kyber-encapsulated key
/// * `nonce` - The nonce used for AES-GCM encryption
/// * `signature` - The Dilithium signature to verify
/// * `my_keypair` - The recipient's Kyber key pair for decryption
/// * `sender_verify_key` - The sender's Dilithium public key for verification
///
/// # Returns
///
/// The decrypted plaintext message if the signature is valid
///
/// # Errors
///
/// Returns an error if:
/// * The signature is invalid (message may be tampered with or from an impostor)
/// * Decryption fails (malformed message)
/// * Any cryptographic operation fails
///
/// # Security Properties
///
/// 1. Verifies the message's integrity and authenticity before attempting decryption
/// 2. Prevents attacks that might use decryption as an oracle
/// 3. Provides complete end-to-end security with post-quantum algorithms
pub fn decrypt_and_verify_message(
    encrypted_message: &[u8],
    encapsulated_key: &[u8],
    nonce: &[u8],
    signature: &[u8],
    my_keypair: &crate::kyber::KyberKeyPair,
    sender_verify_key: &crate::dilithium::DilithiumPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    // Verify the signature
    let mut to_verify = Vec::new();
    to_verify.extend_from_slice(encrypted_message);
    to_verify.extend_from_slice(encapsulated_key);
    to_verify.extend_from_slice(nonce);

    let is_valid = verify_message(&to_verify, signature, sender_verify_key)?;

    if !is_valid {
        return Err(CryptoError::dilithium_error(
            "signature_verification",
            "Signature verification failed",
            crate::error::error_codes::DILITHIUM_VERIFICATION_FAILED,
        ));
    }

    // Decrypt the message
    let plaintext = aes::decrypt(
        encrypted_message,
        &my_keypair.decapsulate(encapsulated_key)?,
        nonce,
        None,
    )?;

    Ok(plaintext)
}
