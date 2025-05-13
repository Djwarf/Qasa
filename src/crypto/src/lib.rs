/*!
 * QaSa Cryptography Module
 *
 * This module implements post-quantum cryptographic primitives for the QaSa
 * secure chat application, with a focus on providing quantum-resistant security.
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

// Re-export main types for convenience
pub use dilithium::DilithiumKeyPair;
pub use dilithium::DilithiumPublicKey;
pub use dilithium::DilithiumVariant;
pub use error::CryptoError;
pub use kyber::KyberKeyPair;
pub use kyber::KyberPublicKey;
pub use kyber::KyberVariant;

/// Initialize the cryptography module.
/// This function should be called before using any cryptographic functions.
/// It performs any necessary setup for the underlying cryptographic libraries.
///
/// # Returns
///
/// `Ok(())` if initialization is successful, or an error if initialization fails
pub fn init() -> Result<(), CryptoError> {
    // Currently, no special initialization is needed, but this function exists
    // to provide a consistent API that can accommodate future requirements
    Ok(())
}

/// Provides a simplified interface to the most commonly used cryptographic operations.
/// 
/// This aims to make the library easier to use with reasonable defaults.
pub mod prelude {
    pub use crate::CryptoError;
    pub use crate::KyberKeyPair;
    pub use crate::KyberPublicKey;
    pub use crate::KyberVariant;
    pub use crate::DilithiumKeyPair;
    pub use crate::DilithiumPublicKey;
    pub use crate::DilithiumVariant;
    pub use crate::init;
    pub use crate::encrypt_message;
    pub use crate::decrypt_message;
    pub use crate::sign_message;
    pub use crate::verify_message;
    pub use crate::encrypt_and_sign_message;
    pub use crate::decrypt_and_verify_message;
    pub use crate::key_management::derive_key_from_password;
    pub use crate::key_management::verify_password;
    pub use crate::key_management::change_password;
    pub use crate::key_management::DerivedKey;
    pub use crate::key_management::KeyDerivationParams;
    pub use crate::key_management::store_kyber_keypair;
    pub use crate::key_management::load_kyber_keypair;
    pub use crate::key_management::store_dilithium_keypair;
    pub use crate::key_management::load_dilithium_keypair;
    pub use crate::key_management::list_keys;
    pub use crate::key_management::delete_key;
    pub use crate::key_management::export_key;
    pub use crate::key_management::import_key;
    pub use crate::key_management::rotate_kyber_keypair;
    pub use crate::key_management::rotate_dilithium_keypair;
    pub use crate::key_management::RotationPolicy;
    pub use crate::key_management::KeyRotationMetadata;
    pub use crate::key_management::KeyAgeSummary;
    pub use crate::key_management::password::high_security_params;
    pub use crate::secure_memory::SecureBuffer;
    pub use crate::secure_memory::SecureBytes;
    pub use crate::secure_memory::with_secure_scope;
    
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
    pub fn open_secure_message(
        encrypted_message: &[u8],
        recipient_private_key: &crate::kyber::KyberKeyPair,
        sender_verify_key: &crate::dilithium::DilithiumPublicKey,
    ) -> Result<Vec<u8>, crate::CryptoError> {
        // Deserialize the signed package
        let signed_package: SignedPackage = bincode::deserialize(encrypted_message)
            .map_err(|e| crate::CryptoError::SerializationError(format!("Failed to deserialize message: {}", e)))?;
        
        // Verify the signature
        let verification_result = crate::dilithium::DilithiumKeyPair::verify_with_public_key(
            sender_verify_key.algorithm,
            &sender_verify_key.public_key,
            &signed_package.message_data,
            &signed_package.signature,
        )?;
        
        if !verification_result {
            return Err(crate::CryptoError::SignatureVerificationError(
                "Message signature verification failed".to_string(),
            ));
        }
        
        // Deserialize the verified message package
        let message_package: MessagePackage = bincode::deserialize(&signed_package.message_data)
            .map_err(|e| crate::CryptoError::SerializationError(format!("Failed to deserialize message package: {}", e)))?;
        
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
        
        // Generate keys for Alice and Bob
        let alice_enc_keys = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        let alice_sig_keys = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
        
        let bob_enc_keys = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        let bob_sig_keys = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
        
        // Extract public keys
        let _alice_enc_pub = alice_enc_keys.public_key();
        let alice_sig_pub = alice_sig_keys.public_key();
        
        let bob_enc_pub = bob_enc_keys.public_key();
        let _bob_sig_pub = bob_sig_keys.public_key();
        
        // Test message from Alice to Bob
        let message = b"Hello Bob, this is a secure message from Alice!";
        
        // Alice creates a secure message for Bob
        let secure_msg = create_secure_message(
            message,
            &bob_enc_pub,
            &alice_sig_keys,
        ).unwrap();
        
        // Bob receives and opens the message
        let decrypted = open_secure_message(
            &secure_msg,
            &bob_enc_keys,
            &alice_sig_pub,
        ).unwrap();
        
        // Verify the message content
        assert_eq!(decrypted, message);
    }
}

/// Function to encrypt a message for a specific recipient
/// 
/// This is a convenience function that combines Kyber KEM for key exchange
/// and AES-GCM for encryption to simplify the encryption process.
///
/// # Arguments
///
/// * `message` - The message to encrypt
/// * `recipient_public_key` - The recipient's Kyber public key
///
/// # Returns
///
/// A tuple containing (ciphertext, encapsulated_key, nonce) or an error
pub fn encrypt_message(
    message: &[u8],
    recipient_public_key: &kyber::KyberPublicKey,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), CryptoError> {
    // Perform key encapsulation
    let (encapsulated_key, shared_secret) = recipient_public_key.encapsulate()?;
    
    // Encrypt the message with the shared secret
    let (encrypted_message, nonce) = aes::encrypt(message, &shared_secret, None)?;
    
    Ok((encrypted_message, encapsulated_key, nonce))
}

/// Function to decrypt a message received from a sender
///
/// This is a convenience function that combines Kyber KEM for key recovery
/// and AES-GCM for decryption to simplify the decryption process.
///
/// # Arguments
///
/// * `encrypted_message` - The encrypted message
/// * `encapsulated_key` - The encapsulated key from the sender
/// * `nonce` - The nonce used for encryption
/// * `my_keypair` - Your Kyber key pair
///
/// # Returns
///
/// The decrypted message or an error
pub fn decrypt_message(
    encrypted_message: &[u8],
    encapsulated_key: &[u8],
    nonce: &[u8],
    my_keypair: &kyber::KyberKeyPair,
) -> Result<Vec<u8>, CryptoError> {
    // Recover the shared secret
    let shared_secret = my_keypair.decapsulate(encapsulated_key)?;
    
    // Decrypt the message with the shared secret
    let plaintext = aes::decrypt(encrypted_message, &shared_secret, nonce, None)?;
    
    Ok(plaintext)
}

/// Function to sign a message
///
/// # Arguments
///
/// * `message` - The message to sign
/// * `signing_key` - Your Dilithium key pair
///
/// # Returns
///
/// The signature or an error
pub fn sign_message(
    message: &[u8],
    signing_key: &dilithium::DilithiumKeyPair,
) -> Result<Vec<u8>, CryptoError> {
    signing_key.sign(message)
}

/// Function to verify a signed message
///
/// # Arguments
///
/// * `message` - The message to verify
/// * `signature` - The signature to verify
/// * `sender_verify_key` - The sender's Dilithium public key
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise, or an error
pub fn verify_message(
    message: &[u8],
    signature: &[u8],
    sender_verify_key: &dilithium::DilithiumPublicKey,
) -> Result<bool, CryptoError> {
    sender_verify_key.verify(message, signature)
}

/// Function to encrypt and sign a message in one operation
///
/// # Arguments
///
/// * `message` - The message to encrypt and sign
/// * `recipient_public_key` - The recipient's Kyber public key
/// * `signing_key` - Your Dilithium key pair
///
/// # Returns
///
/// A tuple containing (encrypted_message, encapsulated_key, nonce, signature) or an error
pub fn encrypt_and_sign_message(
    message: &[u8],
    recipient_public_key: &kyber::KyberPublicKey,
    signing_key: &dilithium::DilithiumKeyPair,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), CryptoError> {
    // Encrypt the message
    let (encrypted_message, encapsulated_key, nonce) = encrypt_message(message, recipient_public_key)?;
    
    // Sign the encrypted message + encapsulated key (to prevent tampering)
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(&encrypted_message);
    to_sign.extend_from_slice(&encapsulated_key);
    to_sign.extend_from_slice(&nonce);
    
    let signature = sign_message(&to_sign, signing_key)?;
    
    Ok((encrypted_message, encapsulated_key, nonce, signature))
}

/// Function to decrypt and verify a signed and encrypted message
///
/// # Arguments
///
/// * `encrypted_message` - The encrypted message
/// * `encapsulated_key` - The encapsulated key
/// * `nonce` - The nonce used for encryption
/// * `signature` - The signature to verify
/// * `my_keypair` - Your Kyber key pair
/// * `sender_verify_key` - The sender's Dilithium public key
///
/// # Returns
///
/// The decrypted message if the signature is valid, or an error
pub fn decrypt_and_verify_message(
    encrypted_message: &[u8],
    encapsulated_key: &[u8],
    nonce: &[u8],
    signature: &[u8],
    my_keypair: &kyber::KyberKeyPair,
    sender_verify_key: &dilithium::DilithiumPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    // Verify the signature
    let mut to_verify = Vec::new();
    to_verify.extend_from_slice(encrypted_message);
    to_verify.extend_from_slice(encapsulated_key);
    to_verify.extend_from_slice(nonce);
    
    let is_valid = verify_message(&to_verify, signature, sender_verify_key)?;
    
    if !is_valid {
        return Err(CryptoError::SignatureVerificationError(
            "Signature verification failed".to_string(),
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
