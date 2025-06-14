//! ChaCha20 Stream Cipher Implementation
//!
//! This module provides an implementation of the ChaCha20 stream cipher as specified in RFC 8439.
//! ChaCha20 is a stream cipher developed by Daniel J. Bernstein and is used as a replacement for
//! the older RC4 cipher due to its improved security and performance characteristics.

use std::convert::TryInto;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error::{CryptoError, CryptoResult};
use crate::utils;

/// Size of ChaCha20 key in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;

/// Size of ChaCha20 nonce in bytes
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// Size of ChaCha20 block in bytes
pub const CHACHA20_BLOCK_SIZE: usize = 64;

/// ChaCha20 key
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct ChaCha20Key {
    key: [u8; CHACHA20_KEY_SIZE],
}

/// ChaCha20 nonce
#[derive(Debug, Clone, Copy)]
pub struct ChaCha20Nonce {
    nonce: [u8; CHACHA20_NONCE_SIZE],
}

/// ChaCha20 state (16 32-bit words)
#[derive(Debug, Clone, ZeroizeOnDrop)]
struct ChaCha20State {
    state: [u32; 16],
}

impl ChaCha20Key {
    /// Create a new ChaCha20 key from bytes
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != CHACHA20_KEY_SIZE {
            return Err(CryptoError::invalid_parameter(
                "key",
                &format!("{} bytes", CHACHA20_KEY_SIZE),
                &format!("{} bytes", key.len()),
            ));
        }

        let mut key_array = [0u8; CHACHA20_KEY_SIZE];
        key_array.copy_from_slice(key);

        Ok(Self { key: key_array })
    }

    /// Generate a random ChaCha20 key
    pub fn generate() -> CryptoResult<Self> {
        let key = utils::random_bytes(CHACHA20_KEY_SIZE)?;
        Self::new(&key)
    }
}

impl Zeroize for ChaCha20Key {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl ChaCha20Nonce {
    /// Create a new ChaCha20 nonce from bytes
    pub fn new(nonce: &[u8]) -> CryptoResult<Self> {
        if nonce.len() != CHACHA20_NONCE_SIZE {
            return Err(CryptoError::invalid_parameter(
                "nonce",
                &format!("{} bytes", CHACHA20_NONCE_SIZE),
                &format!("{} bytes", nonce.len()),
            ));
        }

        let mut nonce_array = [0u8; CHACHA20_NONCE_SIZE];
        nonce_array.copy_from_slice(nonce);

        Ok(Self { nonce: nonce_array })
    }

    /// Generate a random ChaCha20 nonce
    pub fn generate() -> CryptoResult<Self> {
        let nonce = utils::random_bytes(CHACHA20_NONCE_SIZE)?;
        Self::new(&nonce)
    }
}

impl ChaCha20State {
    /// Initialize ChaCha20 state with key, nonce, and counter
    fn new(key: &ChaCha20Key, nonce: &ChaCha20Nonce, counter: u32) -> Self {
        let mut state = [0u32; 16];

        // Constants "expand 32-byte k"
        state[0] = 0x61707865; // "expa"
        state[1] = 0x3320646e; // "nd 3"
        state[2] = 0x79622d32; // "2-by"
        state[3] = 0x6b206574; // "te k"

        // Key (8 words)
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes(
                key.key[i * 4..(i + 1) * 4]
                    .try_into()
                    .expect("Slice with incorrect length"),
            );
        }

        // Counter (1 word)
        state[12] = counter;

        // Nonce (3 words)
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes(
                nonce.nonce[i * 4..(i + 1) * 4]
                    .try_into()
                    .expect("Slice with incorrect length"),
            );
        }

        Self { state }
    }

    /// Quarter round function for ChaCha20
    #[inline]
    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        self.state[a] = self.state[a].wrapping_add(self.state[b]);
        self.state[d] ^= self.state[a];
        self.state[d] = self.state[d].rotate_left(16);

        self.state[c] = self.state[c].wrapping_add(self.state[d]);
        self.state[b] ^= self.state[c];
        self.state[b] = self.state[b].rotate_left(12);

        self.state[a] = self.state[a].wrapping_add(self.state[b]);
        self.state[d] ^= self.state[a];
        self.state[d] = self.state[d].rotate_left(8);

        self.state[c] = self.state[c].wrapping_add(self.state[d]);
        self.state[b] ^= self.state[c];
        self.state[b] = self.state[b].rotate_left(7);
    }

    /// Perform ChaCha20 block function (20 rounds)
    fn block(&mut self) -> [u8; CHACHA20_BLOCK_SIZE] {
        let initial_state = self.state;

        // 10 double rounds (20 rounds total)
        for _ in 0..10 {
            // Column round
            self.quarter_round(0, 4, 8, 12);
            self.quarter_round(1, 5, 9, 13);
            self.quarter_round(2, 6, 10, 14);
            self.quarter_round(3, 7, 11, 15);

            // Diagonal round
            self.quarter_round(0, 5, 10, 15);
            self.quarter_round(1, 6, 11, 12);
            self.quarter_round(2, 7, 8, 13);
            self.quarter_round(3, 4, 9, 14);
        }

        // Add initial state to the result
        for i in 0..16 {
            self.state[i] = self.state[i].wrapping_add(initial_state[i]);
        }

        // Convert to bytes (little-endian)
        let mut output = [0u8; CHACHA20_BLOCK_SIZE];
        for i in 0..16 {
            output[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_le_bytes());
        }

        // Restore initial state for next block
        self.state = initial_state;
        
        output
    }
}

/// Encrypt or decrypt data using ChaCha20 stream cipher
///
/// Since ChaCha20 is a stream cipher, encryption and decryption are the same operation.
///
/// # Arguments
///
/// * `data` - Data to encrypt/decrypt
/// * `key` - ChaCha20 key
/// * `nonce` - ChaCha20 nonce
/// * `counter` - Initial counter value (usually 0 or 1)
///
/// # Returns
///
/// Encrypted/decrypted data
pub fn chacha20_process(data: &[u8], key: &ChaCha20Key, nonce: &ChaCha20Nonce, counter: u32) -> Vec<u8> {
    let mut result = vec![0u8; data.len()];
    
    // Process data in blocks
    let mut offset = 0;
    let mut counter_value = counter;
    
    while offset < data.len() {
        // Generate keystream block
        let mut state = ChaCha20State::new(key, nonce, counter_value);
        let keystream = state.block();
        
        // XOR data with keystream
        let block_size = std::cmp::min(CHACHA20_BLOCK_SIZE, data.len() - offset);
        for i in 0..block_size {
            result[offset + i] = data[offset + i] ^ keystream[i];
        }
        
        // Move to next block
        offset += CHACHA20_BLOCK_SIZE;
        counter_value += 1;
    }
    
    result
}

/// Encrypt data using ChaCha20 stream cipher
pub fn encrypt(data: &[u8], key: &ChaCha20Key, nonce: &ChaCha20Nonce, counter: u32) -> Vec<u8> {
    chacha20_process(data, key, nonce, counter)
}

/// Decrypt data using ChaCha20 stream cipher
pub fn decrypt(data: &[u8], key: &ChaCha20Key, nonce: &ChaCha20Nonce, counter: u32) -> Vec<u8> {
    chacha20_process(data, key, nonce, counter)
} 