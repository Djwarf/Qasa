// Implementation of AES-GCM for symmetric encryption
// This file contains code moved from src/aes.rs

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};

use crate::error::CryptoError;
use crate::utils;

/// AES-256-GCM cipher for authenticated encryption
pub struct AesGcm {
    cipher: Aes256Gcm,
}

impl AesGcm {
    /// Create a new AES-GCM cipher with the given key
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte key (e.g., from Kyber KEM)
    ///
    /// # Returns
    ///
    /// A new AesGcm cipher or an error
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidParameterError(format!(
                "AES-256-GCM requires a 32-byte key, got {}",
                key.len()
            )));
        }

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        Ok(Self { cipher })
    }

    /// Generate a random nonce for encryption
    ///
    /// # Returns
    ///
    /// A 12-byte nonce
    pub fn generate_nonce() -> Vec<u8> {
        Aes256Gcm::generate_nonce(&mut OsRng).to_vec()
    }

    /// Encrypt plaintext using AES-GCM with associated data
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt
    /// * `nonce` - A 12-byte nonce (should be unique for each encryption)
    /// * `associated_data` - Additional data to authenticate but not encrypt
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext or an error
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidParameterError(format!(
                "AES-GCM nonce must be 12 bytes, got {}",
                nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };

        self.cipher
            .encrypt(nonce, payload)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))
    }

    /// Decrypt ciphertext using AES-GCM with associated data
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data
    /// * `nonce` - The same 12-byte nonce used for encryption
    /// * `associated_data` - The same additional data used for encryption
    ///
    /// # Returns
    ///
    /// The decrypted plaintext or an error
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidParameterError(format!(
                "AES-GCM nonce must be 12 bytes, got {}",
                nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))
    }
}

/// Convenience function to encrypt data using AES-GCM
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt
/// * `key` - A 32-byte key (e.g., from Kyber KEM)
/// * `associated_data` - Additional data to authenticate (can be empty)
///
/// # Returns
///
/// A tuple containing (ciphertext, nonce) or an error
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = AesGcm::new(key)?;
    let nonce = AesGcm::generate_nonce();
    let aad = associated_data.unwrap_or(&[]);
    let ciphertext = cipher.encrypt(plaintext, &nonce, aad)?;
    Ok((ciphertext, nonce))
}

/// Convenience function to decrypt data using AES-GCM
///
/// # Arguments
///
/// * `ciphertext` - The encrypted data
/// * `key` - The same 32-byte key used for encryption
/// * `nonce` - The same nonce used for encryption
/// * `associated_data` - The same additional data used for encryption (can be empty)
///
/// # Returns
///
/// The decrypted plaintext or an error
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = AesGcm::new(key)?;
    let aad = associated_data.unwrap_or(&[]);
    cipher.decrypt(ciphertext, nonce, aad)
}

/// Generates a secure random AES key
pub fn generate_key() -> Vec<u8> {
    utils::random_bytes(32).unwrap_or_else(|_| vec![0; 32])
}

// Additional AES-related functions would be defined here
