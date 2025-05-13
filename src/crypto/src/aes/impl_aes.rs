use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use std::sync::Arc;

use crate::error::CryptoError;

/// AES-256-GCM cipher for authenticated encryption
#[derive(Clone)]
pub struct AesGcm {
    cipher: Arc<Aes256Gcm>,
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
        let cipher = Arc::new(Aes256Gcm::new(key));

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

    /// Encrypt plaintext using AES-GCM
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt
    /// * `nonce` - A 12-byte nonce (should be unique for each encryption)
    /// * `associated_data` - Additional data to authenticate but not encrypt (optional)
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext or an error
    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8], associated_data: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidParameterError(format!(
                "AES-GCM nonce must be 12 bytes, got {}",
                nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(nonce);
        
        // Create proper payload with AAD if provided
        let aad = associated_data.unwrap_or(&[]);
        
        // Use Payload struct to associate AAD with the plaintext
        let payload = Payload { msg: plaintext, aad };
        
        // Encrypt using the Aead trait
        self.cipher.encrypt(nonce, payload)
            .map_err(|e| CryptoError::EncryptionError(format!("AES-GCM encryption failed: {}", e)))
    }

    /// Decrypt ciphertext using AES-GCM
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data
    /// * `nonce` - The same 12-byte nonce used for encryption
    /// * `associated_data` - The same additional data used for encryption (optional)
    ///
    /// # Returns
    ///
    /// The decrypted plaintext or an error
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], associated_data: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidParameterError(format!(
                "AES-GCM nonce must be 12 bytes, got {}",
                nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(nonce);
        
        // Create proper payload with AAD if provided
        let aad = associated_data.unwrap_or(&[]);
        
        // Use Payload struct to authenticate AAD with the ciphertext
        let payload = Payload { msg: ciphertext, aad };
        
        // Decrypt using the Aead trait
        self.cipher.decrypt(nonce, payload)
            .map_err(|e| CryptoError::DecryptionError(format!("AES-GCM decryption failed: {}", e)))
    }
}

/// Convenience function to encrypt data using AES-GCM
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt
/// * `key` - A 32-byte key (e.g., from Kyber KEM)
/// * `associated_data` - Additional data to authenticate (optional)
///
/// # Returns
///
/// A tuple containing (ciphertext, nonce) or an error
pub fn encrypt(plaintext: &[u8], key: &[u8], associated_data: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = AesGcm::new(key)?;
    let nonce = AesGcm::generate_nonce();
    let ciphertext = cipher.encrypt(plaintext, &nonce, associated_data)?;
    Ok((ciphertext, nonce))
}

/// Convenience function to decrypt data using AES-GCM
///
/// # Arguments
///
/// * `ciphertext` - The encrypted data
/// * `key` - The same 32-byte key used for encryption
/// * `nonce` - The same nonce used for encryption
/// * `associated_data` - The same additional data used for encryption (optional)
///
/// # Returns
///
/// The decrypted plaintext or an error
pub fn decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8], associated_data: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
    let cipher = AesGcm::new(key)?;
    cipher.decrypt(ciphertext, nonce, associated_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    
    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = utils::random_bytes(32).unwrap();
        let plaintext = b"Hello, world!";
        let aad = b"Additional data";
        
        let (ciphertext, nonce) = encrypt(plaintext, &key, Some(aad)).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce, Some(aad)).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aes_gcm_without_aad() {
        let key = utils::random_bytes(32).unwrap();
        let plaintext = b"This is a test message without AAD";

        // Encrypt without associated data
        let (ciphertext, nonce) = encrypt(plaintext, &key, None).unwrap();
        
        // Decrypt without associated data
        let decrypted = decrypt(&ciphertext, &key, &nonce, None).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_invalid_nonce() {
        let key = utils::random_bytes(32).unwrap();
        let cipher = AesGcm::new(&key).unwrap();
        let plaintext = b"This is a test message";
        let invalid_nonce = vec![0; 10]; // Too short

        let result = cipher.encrypt(plaintext, &invalid_nonce, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_invalid_key() {
        let key = utils::random_bytes(16).unwrap(); // Too short for AES-256
        let result = AesGcm::new(&key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_tampered_ciphertext() {
        let key = utils::random_bytes(32).unwrap();
        let plaintext = b"This is a test message for tamper detection";
        let associated_data = b"additional data";

        // Encrypt
        let (mut ciphertext, nonce) = encrypt(plaintext, &key, Some(associated_data)).unwrap();

        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        }

        // Try to decrypt
        let result = decrypt(&ciphertext, &key, &nonce, Some(associated_data));
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_wrong_key() {
        let key1 = utils::random_bytes(32).unwrap();
        let key2 = utils::random_bytes(32).unwrap();
        let plaintext = b"This is a test message for wrong key";

        // Encrypt with key1
        let (ciphertext, nonce) = encrypt(plaintext, &key1, None).unwrap();

        // Try to decrypt with key2
        let result = decrypt(&ciphertext, &key2, &nonce, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_with_large_data() {
        let key = utils::random_bytes(32).unwrap();
        let plaintext = vec![0xAA; 1000]; // 1KB of data
        let associated_data = b"large data test";

        let (ciphertext, nonce) = encrypt(&plaintext, &key, Some(associated_data)).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce, Some(associated_data)).unwrap();

        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_cipher_cloning() {
        let key = utils::random_bytes(32).unwrap();
        let cipher1 = AesGcm::new(&key).unwrap();
        let cipher2 = cipher1.clone();
        
        let plaintext = b"Testing cipher cloning";
        let nonce = AesGcm::generate_nonce();
        
        let ciphertext1 = cipher1.encrypt(plaintext, &nonce, None).unwrap();
        let plaintext2 = cipher2.decrypt(&ciphertext1, &nonce, None).unwrap();
        
        assert_eq!(plaintext, &plaintext2[..]);
    }
    
    #[test]
    fn test_empty_vs_none_aad() {
        // Test behavior with empty AAD vs no AAD with the aes-gcm crate
        let key = utils::random_bytes(32).unwrap();
        let plaintext = b"Testing empty vs none AAD";
        let nonce = AesGcm::generate_nonce();
        
        let cipher = AesGcm::new(&key).unwrap();
        
        // Encrypt with empty AAD
        let ciphertext1 = cipher.encrypt(plaintext, &nonce, Some(&[])).unwrap();
        
        // Encrypt with no AAD (None)
        let ciphertext2 = cipher.encrypt(plaintext, &nonce, None).unwrap();
        
        // With the aes-gcm crate, empty AAD and None are treated the same way
        // The ciphertexts should be identical
        assert_eq!(ciphertext1, ciphertext2, "Empty AAD and None should produce the same ciphertext");
        
        // Verify cross-decryption works
        let decrypted1 = cipher.decrypt(&ciphertext1, &nonce, None).unwrap();
        let decrypted2 = cipher.decrypt(&ciphertext2, &nonce, Some(&[])).unwrap();
        
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
} 