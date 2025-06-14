//! Hybrid Encryption
//!
//! This module provides functions for hybrid encryption combining classical and
//! post-quantum algorithms for enhanced security.

use std::fmt;
use std::fmt::Display;

use crate::error::{CryptoError, CryptoResult};
use crate::hybrid::hybrid_kem::{
    HybridKemKeyPair,
    HybridKemPublicKey,
    HybridKemCiphertext,
    HybridKemVariant,
};
use crate::aes::{AesMode, AesKey, AesNonce};
use crate::utils;

/// Parameters for hybrid encryption
#[derive(Debug, Clone, Copy)]
pub struct HybridEncryptionParameters {
    /// KEM variant to use
    pub kem_variant: HybridKemVariant,
    /// AES mode to use for symmetric encryption
    pub aes_mode: AesMode,
}

/// Encrypt data using hybrid encryption
///
/// This function:
/// 1. Encapsulates a shared secret using the recipient's public key
/// 2. Uses the shared secret to derive an AES key
/// 3. Encrypts the data using AES
/// 4. Returns the KEM ciphertext and encrypted data
pub fn encrypt_hybrid(
    recipient_public_key: &HybridKemPublicKey,
    data: &[u8],
    params: HybridEncryptionParameters,
) -> CryptoResult<(HybridKemCiphertext, Vec<u8>)> {
    // Encapsulate to get shared secret and KEM ciphertext
    let (kem_ciphertext, shared_secret) = recipient_public_key.encapsulate()?;
    
    // Derive AES key and nonce from shared secret
    let (aes_key, aes_nonce) = derive_encryption_key(&shared_secret, params.aes_mode)?;
    
    // Encrypt data with AES
    let encrypted_data = match params.aes_mode {
        AesMode::Gcm256 => {
            let key = AesKey::new_256(&aes_key)?;
            let nonce = AesNonce::new(&aes_nonce)?;
            key.encrypt_gcm(&data, &nonce, None)?
        },
        AesMode::Ctr256 => {
            let key = AesKey::new_256(&aes_key)?;
            let nonce = AesNonce::new(&aes_nonce)?;
            key.encrypt_ctr(&data, &nonce)?
        },
        // Add other modes as needed
        _ => {
            return Err(CryptoError::invalid_parameter(
                "aes_mode",
                "AesMode::Gcm256 or AesMode::Ctr256",
                "unsupported mode",
            ));
        }
    };
    
    Ok((kem_ciphertext, encrypted_data))
}

/// Decrypt data using hybrid encryption
///
/// This function:
/// 1. Decapsulates the shared secret using the recipient's private key and KEM ciphertext
/// 2. Uses the shared secret to derive the AES key
/// 3. Decrypts the data using AES
/// 4. Returns the decrypted data
pub fn decrypt_hybrid(
    recipient_key_pair: &HybridKemKeyPair,
    kem_ciphertext: &HybridKemCiphertext,
    encrypted_data: &[u8],
    params: HybridEncryptionParameters,
) -> CryptoResult<Vec<u8>> {
    // Decapsulate to recover shared secret
    let shared_secret = recipient_key_pair.decapsulate(kem_ciphertext)?;
    
    // Derive AES key and nonce from shared secret
    let (aes_key, aes_nonce) = derive_encryption_key(&shared_secret, params.aes_mode)?;
    
    // Decrypt data with AES
    let decrypted_data = match params.aes_mode {
        AesMode::Gcm256 => {
            let key = AesKey::new_256(&aes_key)?;
            let nonce = AesNonce::new(&aes_nonce)?;
            key.decrypt_gcm(&encrypted_data, &nonce, None)?
        },
        AesMode::Ctr256 => {
            let key = AesKey::new_256(&aes_key)?;
            let nonce = AesNonce::new(&aes_nonce)?;
            key.decrypt_ctr(&encrypted_data, &nonce)?
        },
        // Add other modes as needed
        _ => {
            return Err(CryptoError::invalid_parameter(
                "aes_mode",
                "AesMode::Gcm256 or AesMode::Ctr256",
                "unsupported mode",
            ));
        }
    };
    
    Ok(decrypted_data)
}

/// Derive encryption key and nonce from shared secret
fn derive_encryption_key(shared_secret: &[u8], aes_mode: AesMode) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    // Use HKDF to derive key material
    let info = b"QaSa Hybrid Encryption";
    
    // Derive key
    let key_size = match aes_mode {
        AesMode::Gcm256 | AesMode::Ctr256 => 32, // 256 bits
        AesMode::Gcm128 | AesMode::Ctr128 => 16, // 128 bits
        _ => {
            return Err(CryptoError::invalid_parameter(
                "aes_mode",
                "supported AES mode",
                "unsupported mode",
            ));
        }
    };
    
    // Derive nonce
    let nonce_size = match aes_mode {
        AesMode::Gcm256 | AesMode::Gcm128 => 12, // 96 bits for GCM
        AesMode::Ctr256 | AesMode::Ctr128 => 16, // 128 bits for CTR
        _ => {
            return Err(CryptoError::invalid_parameter(
                "aes_mode",
                "supported AES mode",
                "unsupported mode",
            ));
        }
    };
    
    // Derive key material
    let mut key_material = utils::hkdf_sha256(
        shared_secret,
        None,
        info,
        key_size + nonce_size,
    );
    
    // Split into key and nonce
    let nonce = key_material.split_off(key_size);
    
    Ok((key_material, nonce))
} 