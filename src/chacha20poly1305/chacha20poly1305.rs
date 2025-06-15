//! ChaCha20-Poly1305 AEAD Cipher Implementation
//!
//! This module provides an implementation of the ChaCha20-Poly1305 authenticated encryption
//! with associated data (AEAD) cipher as specified in RFC 8439.

use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error::{CryptoError, CryptoResult, error_codes};
use crate::utils;

use super::chacha20::{
    ChaCha20Key,
    ChaCha20Nonce,
    chacha20_process,
    CHACHA20_KEY_SIZE,
    CHACHA20_NONCE_SIZE,
};
use super::poly1305::{
    Poly1305Key,
    poly1305_mac,
    poly1305_verify,
    POLY1305_TAG_SIZE,
};

/// Size of ChaCha20-Poly1305 key in bytes
pub const CHACHA20_POLY1305_KEY_SIZE: usize = CHACHA20_KEY_SIZE;

/// Size of ChaCha20-Poly1305 nonce in bytes
pub const CHACHA20_POLY1305_NONCE_SIZE: usize = CHACHA20_NONCE_SIZE;

/// Size of ChaCha20-Poly1305 authentication tag in bytes
pub const CHACHA20_POLY1305_TAG_SIZE: usize = POLY1305_TAG_SIZE;

/// ChaCha20-Poly1305 key
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct ChaCha20Poly1305Key {
    key: [u8; CHACHA20_POLY1305_KEY_SIZE],
}

/// ChaCha20-Poly1305 nonce
#[derive(Debug, Clone, Copy)]
pub struct ChaCha20Poly1305Nonce {
    nonce: [u8; CHACHA20_POLY1305_NONCE_SIZE],
}

/// ChaCha20-Poly1305 AEAD cipher
#[derive(Debug)]
pub struct ChaCha20Poly1305 {
    key: ChaCha20Poly1305Key,
}

impl ChaCha20Poly1305Key {
    /// Create a new ChaCha20-Poly1305 key from bytes
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != CHACHA20_POLY1305_KEY_SIZE {
            return Err(CryptoError::invalid_parameter(
                "key",
                &format!("{} bytes", CHACHA20_POLY1305_KEY_SIZE),
                &format!("{} bytes", key.len()),
            ));
        }

        let mut key_array = [0u8; CHACHA20_POLY1305_KEY_SIZE];
        key_array.copy_from_slice(key);

        Ok(Self { key: key_array })
    }

    /// Generate a random ChaCha20-Poly1305 key
    pub fn generate() -> CryptoResult<Self> {
        let key = utils::random_bytes(CHACHA20_POLY1305_KEY_SIZE)?;
        Self::new(&key)
    }
}

impl Zeroize for ChaCha20Poly1305Key {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl ChaCha20Poly1305Nonce {
    /// Create a new ChaCha20-Poly1305 nonce from bytes
    pub fn new(nonce: &[u8]) -> CryptoResult<Self> {
        if nonce.len() != CHACHA20_POLY1305_NONCE_SIZE {
            return Err(CryptoError::invalid_parameter(
                "nonce",
                &format!("{} bytes", CHACHA20_POLY1305_NONCE_SIZE),
                &format!("{} bytes", nonce.len()),
            ));
        }

        let mut nonce_array = [0u8; CHACHA20_POLY1305_NONCE_SIZE];
        nonce_array.copy_from_slice(nonce);

        Ok(Self { nonce: nonce_array })
    }

    /// Generate a random ChaCha20-Poly1305 nonce
    pub fn generate() -> CryptoResult<Self> {
        let nonce = utils::random_bytes(CHACHA20_POLY1305_NONCE_SIZE)?;
        Self::new(&nonce)
    }
}

impl ChaCha20Poly1305 {
    /// Create a new ChaCha20-Poly1305 instance with the given key
    pub fn new(key: ChaCha20Poly1305Key) -> Self {
        Self { key }
    }

    /// Encrypt and authenticate data
    pub fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>, nonce: &ChaCha20Poly1305Nonce) -> CryptoResult<Vec<u8>> {
        encrypt(plaintext, aad, &self.key, nonce)
    }

    /// Decrypt and verify data
    pub fn decrypt(&self, ciphertext: &[u8], aad: Option<&[u8]>, nonce: &ChaCha20Poly1305Nonce) -> CryptoResult<Vec<u8>> {
        decrypt(ciphertext, aad, &self.key, nonce)
    }
}

/// Derive Poly1305 key from ChaCha20 key and nonce
fn derive_poly1305_key(key: &ChaCha20Poly1305Key, nonce: &ChaCha20Poly1305Nonce) -> CryptoResult<Poly1305Key> {
    // Convert to ChaCha20 types
    let chacha_key = ChaCha20Key::new(&key.key)?;
    let chacha_nonce = ChaCha20Nonce::new(&nonce.nonce)?;
    
    // Generate keystream block with counter 0
    let keystream = super::chacha20::chacha20_keystream_block(&chacha_key, &chacha_nonce, 0);
    
    // Use first 32 bytes as Poly1305 key
    Poly1305Key::new(&keystream[0..32])
}

/// Pad a message to a multiple of 16 bytes
fn pad16(msg: &[u8]) -> Vec<u8> {
    if msg.len() % 16 == 0 {
        return msg.to_vec();
    }
    
    let padding_len = 16 - (msg.len() % 16);
    let mut padded = Vec::with_capacity(msg.len() + padding_len);
    padded.extend_from_slice(msg);
    padded.resize(msg.len() + padding_len, 0);
    padded
}

/// Compute the Poly1305 tag for ChaCha20-Poly1305
fn compute_tag(
    aad: Option<&[u8]>,
    ciphertext: &[u8],
    key: &ChaCha20Poly1305Key,
    nonce: &ChaCha20Poly1305Nonce,
) -> CryptoResult<[u8; POLY1305_TAG_SIZE]> {
    // Derive Poly1305 key
    let poly_key = derive_poly1305_key(key, nonce)?;
    
    // Initialize Poly1305 state
    let mut state = super::poly1305::Poly1305State::new(&poly_key);
    
    // Process AAD if provided
    if let Some(aad_data) = aad {
        state.update(&pad16(aad_data));
    }
    
    // Process ciphertext
    state.update(&pad16(ciphertext));
    
    // Process lengths (little-endian 64-bit unsigned integers)
    let mut length_block = [0u8; 16];
    let aad_len = aad.map_or(0, |a| a.len()) as u64;
    let ciphertext_len = ciphertext.len() as u64;
    
    length_block[0..8].copy_from_slice(&aad_len.to_le_bytes());
    length_block[8..16].copy_from_slice(&ciphertext_len.to_le_bytes());
    
    state.update(&length_block);
    
    // Finalize and return tag
    Ok(state.finalize())
}

/// Encrypt and authenticate data using ChaCha20-Poly1305
///
/// # Arguments
///
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (optional)
/// * `key` - ChaCha20-Poly1305 key
/// * `nonce` - ChaCha20-Poly1305 nonce
///
/// # Returns
///
/// Ciphertext with authentication tag appended
pub fn encrypt(
    plaintext: &[u8],
    aad: Option<&[u8]>,
    key: &ChaCha20Poly1305Key,
    nonce: &ChaCha20Poly1305Nonce,
) -> CryptoResult<Vec<u8>> {
    // Convert to ChaCha20 types
    let chacha_key = ChaCha20Key::new(&key.key)?;
    let chacha_nonce = ChaCha20Nonce::new(&nonce.nonce)?;
    
    // Encrypt plaintext using ChaCha20 with counter 1
    let ciphertext = chacha20_process(plaintext, &chacha_key, &chacha_nonce, 1);
    
    // Compute authentication tag
    let tag = compute_tag(aad, &ciphertext, key, nonce)?;
    
    // Combine ciphertext and tag
    let mut result = Vec::with_capacity(ciphertext.len() + CHACHA20_POLY1305_TAG_SIZE);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag);
    
    Ok(result)
}

/// Decrypt and verify data using ChaCha20-Poly1305
///
/// # Arguments
///
/// * `ciphertext` - Ciphertext with authentication tag appended
/// * `aad` - Additional authenticated data (optional)
/// * `key` - ChaCha20-Poly1305 key
/// * `nonce` - ChaCha20-Poly1305 nonce
///
/// # Returns
///
/// Decrypted plaintext if authentication succeeds
pub fn decrypt(
    ciphertext: &[u8],
    aad: Option<&[u8]>,
    key: &ChaCha20Poly1305Key,
    nonce: &ChaCha20Poly1305Nonce,
) -> CryptoResult<Vec<u8>> {
    // Check ciphertext length
    if ciphertext.len() < CHACHA20_POLY1305_TAG_SIZE {
        return Err(CryptoError::invalid_parameter(
            "ciphertext",
            &format!("at least {} bytes", CHACHA20_POLY1305_TAG_SIZE),
            &format!("{} bytes", ciphertext.len()),
        ));
    }
    
    // Split ciphertext and tag
    let actual_ciphertext = &ciphertext[..ciphertext.len() - CHACHA20_POLY1305_TAG_SIZE];
    let received_tag = &ciphertext[ciphertext.len() - CHACHA20_POLY1305_TAG_SIZE..];
    
    // Compute expected tag
    let expected_tag = compute_tag(aad, actual_ciphertext, key, nonce)?;
    
    // Verify tag (constant-time comparison)
    let mut diff = 0;
    for i in 0..CHACHA20_POLY1305_TAG_SIZE {
        diff |= received_tag[i] ^ expected_tag[i];
    }
    
    if diff != 0 {
        return Err(CryptoError::authentication_error(
            "decrypt",
            "ChaCha20-Poly1305 authentication failed",
            error_codes::CHACHA20POLY1305_AUTHENTICATION_FAILED,
        ));
    }
    
    // Convert to ChaCha20 types
    let chacha_key = ChaCha20Key::new(&key.key)?;
    let chacha_nonce = ChaCha20Nonce::new(&nonce.nonce)?;
    
    // Decrypt ciphertext using ChaCha20 with counter 1
    let plaintext = chacha20_process(actual_ciphertext, &chacha_key, &chacha_nonce, 1);
    
    Ok(plaintext)
} 