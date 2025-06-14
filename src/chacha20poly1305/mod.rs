//! ChaCha20-Poly1305 AEAD Cipher Implementation
//! 
//! This module provides an implementation of the ChaCha20-Poly1305 authenticated encryption
//! with associated data (AEAD) cipher as specified in RFC 8439.
//! 
//! ChaCha20-Poly1305 combines the ChaCha20 stream cipher with the Poly1305 message
//! authentication code (MAC) to provide both confidentiality and authenticity.

mod chacha20;
mod poly1305;
mod chacha20poly1305;
mod tests;

pub use chacha20poly1305::{
    ChaCha20Poly1305,
    ChaCha20Poly1305Key,
    ChaCha20Poly1305Nonce,
    encrypt,
    decrypt,
    CHACHA20_POLY1305_KEY_SIZE,
    CHACHA20_POLY1305_NONCE_SIZE,
    CHACHA20_POLY1305_TAG_SIZE
}; 