//! High-level user-friendly API for QaSa quantum-safe cryptography
//!
//! This module provides simple, easy-to-use functions for common cryptographic operations.
//! All functions use secure defaults and post-quantum algorithms.

use crate::aes::AesGcm;
use crate::dilithium::{DilithiumKeyPair, DilithiumVariant};
use crate::kyber::{KyberKeyPair, KyberVariant};
use crate::{CryptoError, CryptoResult};

/// Simple key generation for encryption
///
/// Generates a new Kyber768 key pair for encryption/decryption.
/// This is the recommended variant for most use cases.
///
/// # Returns
///
/// A new key pair ready for use, or an error if generation fails
///
/// # Example
///
/// ```
/// use qasa::simple::generate_encryption_keys;
///
/// let keys = generate_encryption_keys().unwrap();
/// ```
pub fn generate_encryption_keys() -> CryptoResult<KyberKeyPair> {
    KyberKeyPair::generate(KyberVariant::Kyber768)
}

/// Simple key generation for digital signatures
///
/// Generates a new Dilithium3 key pair for signing/verification.
/// This is the recommended variant for most use cases.
///
/// # Returns
///
/// A new key pair ready for use, or an error if generation fails
///
/// # Example
///
/// ```
/// use qasa::simple::generate_signing_keys;
///
/// let keys = generate_signing_keys().unwrap();
/// ```
pub fn generate_signing_keys() -> CryptoResult<DilithiumKeyPair> {
    DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
}

/// Encrypt a message for a recipient
///
/// Uses hybrid encryption with Kyber KEM + AES-GCM for secure message encryption.
/// The result can be safely transmitted over insecure channels.
///
/// # Arguments
///
/// * `message` - The message to encrypt (any binary data)
/// * `recipient_public_key` - The recipient's public key
///
/// # Returns
///
/// A tuple containing (encrypted_data, encapsulated_key, nonce) that must all
/// be sent to the recipient for decryption
///
/// # Example
///
/// ```
/// use qasa::simple::{generate_encryption_keys, encrypt_for_recipient};
///
/// let recipient_keys = generate_encryption_keys().unwrap();
/// let message = b"Hello, world!";
///
/// let (encrypted, key, nonce) = encrypt_for_recipient(
///     message,
///     &recipient_keys.public_key()
/// ).unwrap();
/// ```
pub fn encrypt_for_recipient(
    message: &[u8],
    recipient_public_key: &crate::kyber::KyberPublicKey,
) -> CryptoResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    crate::encrypt_message(message, recipient_public_key)
}

/// Decrypt a message from a sender
///
/// Decrypts a message that was encrypted with encrypt_for_recipient().
///
/// # Arguments
///
/// * `encrypted_data` - The encrypted message
/// * `encapsulated_key` - The encapsulated key from the sender
/// * `nonce` - The encryption nonce
/// * `recipient_keys` - Your key pair (must match the public key used for encryption)
///
/// # Returns
///
/// The original plaintext message
///
/// # Example
///
/// ```
/// use qasa::simple::{generate_encryption_keys, encrypt_for_recipient, decrypt_from_sender};
///
/// let recipient_keys = generate_encryption_keys().unwrap();
/// let message = b"Hello, world!";
///
/// let (encrypted, key, nonce) = encrypt_for_recipient(
///     message,
///     &recipient_keys.public_key()
/// ).unwrap();
///
/// let decrypted = decrypt_from_sender(&encrypted, &key, &nonce, &recipient_keys).unwrap();
/// assert_eq!(decrypted, message);
/// ```
pub fn decrypt_from_sender(
    encrypted_data: &[u8],
    encapsulated_key: &[u8],
    nonce: &[u8],
    recipient_keys: &KyberKeyPair,
) -> CryptoResult<Vec<u8>> {
    crate::decrypt_message(encrypted_data, encapsulated_key, nonce, recipient_keys)
}

/// Sign a message
///
/// Creates a digital signature for a message using post-quantum cryptography.
/// The signature proves the message came from the holder of the private key.
///
/// # Arguments
///
/// * `message` - The message to sign (any binary data)
/// * `signing_keys` - Your signing key pair
///
/// # Returns
///
/// A digital signature that can be verified by anyone with your public key
///
/// # Example
///
/// ```
/// use qasa::simple::{generate_signing_keys, sign_message};
///
/// let keys = generate_signing_keys().unwrap();
/// let message = b"Important document";
///
/// let signature = sign_message(message, &keys).unwrap();
/// ```
pub fn sign_message(message: &[u8], signing_keys: &DilithiumKeyPair) -> CryptoResult<Vec<u8>> {
    crate::sign_message(message, signing_keys)
}

/// Verify a digital signature
///
/// Checks if a signature is valid for a given message and public key.
/// This proves the message was signed by the holder of the corresponding private key.
///
/// # Arguments
///
/// * `message` - The message that was signed
/// * `signature` - The signature to verify
/// * `signer_public_key` - The public key of the signer
///
/// # Returns
///
/// `Ok(true)` if the signature is valid, `Ok(false)` if invalid, or an error
///
/// # Example
///
/// ```
/// use qasa::simple::{generate_signing_keys, sign_message, verify_signature};
///
/// let keys = generate_signing_keys().unwrap();
/// let message = b"Important document";
///
/// let signature = sign_message(message, &keys).unwrap();
/// let is_valid = verify_signature(message, &signature, &keys.public_key()).unwrap();
/// assert!(is_valid);
/// ```
pub fn verify_signature(
    message: &[u8],
    signature: &[u8],
    signer_public_key: &crate::dilithium::DilithiumPublicKey,
) -> CryptoResult<bool> {
    crate::verify_message(message, signature, signer_public_key)
}

/// Encrypt and sign a message in one operation
///
/// Provides both confidentiality (encryption) and authenticity (digital signature).
/// This is the most secure way to send a message.
///
/// # Arguments
///
/// * `message` - The message to encrypt and sign
/// * `recipient_public_key` - The recipient's encryption public key
/// * `sender_signing_keys` - Your signing key pair
///
/// # Returns
///
/// A tuple containing (encrypted_data, encapsulated_key, nonce, signature)
///
/// # Example
///
/// ```
/// use qasa::simple::{generate_encryption_keys, generate_signing_keys, encrypt_and_sign};
///
/// let recipient_keys = generate_encryption_keys().unwrap();
/// let sender_keys = generate_signing_keys().unwrap();
/// let message = b"Confidential and authenticated message";
///
/// let (encrypted, key, nonce, signature) = encrypt_and_sign(
///     message,
///     &recipient_keys.public_key(),
///     &sender_keys
/// ).unwrap();
/// ```
pub fn encrypt_and_sign(
    message: &[u8],
    recipient_public_key: &crate::kyber::KyberPublicKey,
    sender_signing_keys: &DilithiumKeyPair,
) -> CryptoResult<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    crate::encrypt_and_sign_message(message, recipient_public_key, sender_signing_keys)
}

/// Decrypt and verify a signed encrypted message
///
/// Verifies the signature and then decrypts the message.
/// Only succeeds if both the signature is valid and decryption works.
///
/// # Arguments
///
/// * `encrypted_data` - The encrypted message
/// * `encapsulated_key` - The encapsulated key
/// * `nonce` - The encryption nonce  
/// * `signature` - The digital signature
/// * `recipient_keys` - Your encryption key pair
/// * `sender_public_key` - The sender's signing public key
///
/// # Returns
///
/// The original plaintext message if both verification and decryption succeed
///
/// # Example
///
/// ```
/// use qasa::simple::{
///     generate_encryption_keys, generate_signing_keys,
///     encrypt_and_sign, decrypt_and_verify
/// };
///
/// let recipient_keys = generate_encryption_keys().unwrap();
/// let sender_keys = generate_signing_keys().unwrap();
/// let message = b"Confidential and authenticated message";
///
/// let (encrypted, key, nonce, signature) = encrypt_and_sign(
///     message,
///     &recipient_keys.public_key(),
///     &sender_keys
/// ).unwrap();
///
/// let decrypted = decrypt_and_verify(
///     &encrypted, &key, &nonce, &signature,
///     &recipient_keys,
///     &sender_keys.public_key()
/// ).unwrap();
///
/// assert_eq!(decrypted, message);
/// ```
pub fn decrypt_and_verify(
    encrypted_data: &[u8],
    encapsulated_key: &[u8],
    nonce: &[u8],
    signature: &[u8],
    recipient_keys: &KyberKeyPair,
    sender_public_key: &crate::dilithium::DilithiumPublicKey,
) -> CryptoResult<Vec<u8>> {
    crate::decrypt_and_verify_message(
        encrypted_data,
        encapsulated_key,
        nonce,
        signature,
        recipient_keys,
        sender_public_key,
    )
}
