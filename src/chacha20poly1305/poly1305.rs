//! Poly1305 Message Authentication Code Implementation
//!
//! This module provides an implementation of the Poly1305 message authentication code (MAC)
//! as specified in RFC 8439. Poly1305 is a one-time authenticator designed by Daniel J. Bernstein.

use std::convert::TryInto;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error::{CryptoError, CryptoResult};

/// Size of Poly1305 key in bytes
pub const POLY1305_KEY_SIZE: usize = 32;

/// Size of Poly1305 tag in bytes
pub const POLY1305_TAG_SIZE: usize = 16;

/// Poly1305 key
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct Poly1305Key {
    /// The r part of the key (16 bytes)
    r: [u8; 16],
    /// The s part of the key (16 bytes)
    s: [u8; 16],
}

/// Poly1305 state for incremental MAC computation
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct Poly1305State {
    /// The r part of the key (clamped)
    r: [u32; 5],
    /// The s part of the key
    s: [u32; 4],
    /// Accumulated hash
    h: [u32; 5],
    /// Buffer for partial blocks
    buffer: [u8; 16],
    /// Number of bytes in the buffer
    buffer_size: usize,
    /// Total bytes processed
    total_bytes: usize,
}

impl Poly1305Key {
    /// Create a new Poly1305 key from bytes
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != POLY1305_KEY_SIZE {
            return Err(CryptoError::invalid_parameter(
                "key",
                &format!("{} bytes", POLY1305_KEY_SIZE),
                &format!("{} bytes", key.len()),
            ));
        }

        let mut r = [0u8; 16];
        let mut s = [0u8; 16];

        r.copy_from_slice(&key[0..16]);
        s.copy_from_slice(&key[16..32]);

        Ok(Self { r, s })
    }
}

impl Zeroize for Poly1305Key {
    fn zeroize(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
    }
}

impl Poly1305State {
    /// Create a new Poly1305 state with the given key
    pub fn new(key: &Poly1305Key) -> Self {
        // Clamp r
        let r0 = u32::from_le_bytes(key.r[0..4].try_into().unwrap()) & 0x0fffffff;
        let r1 = u32::from_le_bytes(key.r[4..8].try_into().unwrap()) & 0x0ffffffc;
        let r2 = u32::from_le_bytes(key.r[8..12].try_into().unwrap()) & 0x0ffffffc;
        let r3 = u32::from_le_bytes(key.r[12..16].try_into().unwrap()) & 0x0ffffffc;

        // Convert s to little-endian 32-bit words
        let s0 = u32::from_le_bytes(key.s[0..4].try_into().unwrap());
        let s1 = u32::from_le_bytes(key.s[4..8].try_into().unwrap());
        let s2 = u32::from_le_bytes(key.s[8..12].try_into().unwrap());
        let s3 = u32::from_le_bytes(key.s[12..16].try_into().unwrap());

        Self {
            r: [r0, r1, r2, r3, 0],
            s: [s0, s1, s2, s3],
            h: [0, 0, 0, 0, 0],
            buffer: [0; 16],
            buffer_size: 0,
            total_bytes: 0,
        }
    }

    /// Process a block of data
    fn process_block(&mut self, block: [u8; 16]) {
        // Convert block to little-endian 32-bit words and add 2^128
        let mut n = [0u32; 5];
        n[0] = u32::from_le_bytes(block[0..4].try_into().unwrap());
        n[1] = u32::from_le_bytes(block[4..8].try_into().unwrap());
        n[2] = u32::from_le_bytes(block[8..12].try_into().unwrap());
        n[3] = u32::from_le_bytes(block[12..16].try_into().unwrap());
        n[4] = 1; // 2^128

        // h += n (ADD FIRST) - using u64 to prevent overflow
        let mut h0 = self.h[0] as u64 + n[0] as u64;
        let mut h1 = self.h[1] as u64 + n[1] as u64;
        let mut h2 = self.h[2] as u64 + n[2] as u64;
        let mut h3 = self.h[3] as u64 + n[3] as u64;
        let mut h4 = self.h[4] as u64 + n[4] as u64;

        // h *= r (mod 2^130 - 5) - MULTIPLY SECOND
        let r0: u64 = self.r[0] as u64;
        let r1: u64 = self.r[1] as u64;
        let r2: u64 = self.r[2] as u64;
        let r3: u64 = self.r[3] as u64;
        let r4: u64 = self.r[4] as u64;

        // h = h * r
        let d0: u64 = h0 * r0 + h1 * (5 * r4) + h2 * (5 * r3) + h3 * (5 * r2) + h4 * (5 * r1);
        let mut d1: u64 = h0 * r1 + h1 * r0 + h2 * (5 * r4) + h3 * (5 * r3) + h4 * (5 * r2);
        let mut d2: u64 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r4) + h4 * (5 * r3);
        let mut d3: u64 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r4);
        let mut d4: u64 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        // Partial reduction modulo 2^130 - 5
        let mut c: u64 = d0 >> 26;
        h0 = d0 & 0x3ffffff;
        d1 += c;

        c = d1 >> 26;
        h1 = d1 & 0x3ffffff;
        d2 += c;

        c = d2 >> 26;
        h2 = d2 & 0x3ffffff;
        d3 += c;

        c = d3 >> 26;
        h3 = d3 & 0x3ffffff;
        d4 += c;

        c = d4 >> 26;
        h4 = d4 & 0x3ffffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        // Store back to state
        self.h[0] = h0 as u32;
        self.h[1] = h1 as u32;
        self.h[2] = h2 as u32;
        self.h[3] = h3 as u32;
        self.h[4] = h4 as u32;
    }

    /// Update the state with data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Process any buffered data
        if self.buffer_size > 0 {
            let needed = 16 - self.buffer_size;
            let to_copy = std::cmp::min(needed, data.len());
            self.buffer[self.buffer_size..self.buffer_size + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_size += to_copy;
            offset += to_copy;

            if self.buffer_size == 16 {
                let buffer_copy = self.buffer;
                self.process_block(buffer_copy);
                self.buffer_size = 0;
            }
        }

        // Process full blocks
        while offset + 16 <= data.len() {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[offset..offset + 16]);
            self.process_block(block);
            offset += 16;
        }

        // Buffer remaining data
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_size = remaining;
        }

        self.total_bytes += data.len();
    }

    /// Finalize the MAC and return the tag
    pub fn finalize(mut self) -> [u8; POLY1305_TAG_SIZE] {
        // Process any remaining data
        if self.buffer_size > 0 {
            // Add padding
            self.buffer[self.buffer_size] = 1;
            for i in self.buffer_size + 1..16 {
                self.buffer[i] = 0;
            }
            let buffer_copy = self.buffer;
            self.process_block(buffer_copy);
        }

        // Fully reduce h
        let mut h0: u32 = self.h[0];
        let mut h1: u32 = self.h[1];
        let mut h2: u32 = self.h[2];
        let mut h3: u32 = self.h[3];
        let mut h4: u32 = self.h[4];

        let mut c: u64 = (h1 >> 26) as u64;
        h1 &= 0x3ffffff;
        let mut h2_64 = h2 as u64 + c;

        c = h2_64 >> 26;
        h2 = (h2_64 & 0x3ffffff) as u32;
        let mut h3_64 = h3 as u64 + c;

        c = h3_64 >> 26;
        h3 = (h3_64 & 0x3ffffff) as u32;
        let mut h4_64 = h4 as u64 + c;

        c = h4_64 >> 26;
        h4 = (h4_64 & 0x3ffffff) as u32;
        let mut h0_64 = h0 as u64 + c * 5;

        c = h0_64 >> 26;
        h0 = (h0_64 & 0x3ffffff) as u32;
        let h1_64 = h1 as u64 + c;
        h1 = h1_64 as u32;

        // Compute h - p where p = 2^130 - 5
        // p in radix 2^26 representation is: [0x3fffffb, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff]
        let mut g0: u32 = h0.wrapping_add(5);
        let mut g1: u32 = h1.wrapping_add((g0 >> 26) as u32);
        g0 &= 0x3ffffff;
        let mut g2: u32 = h2.wrapping_add((g1 >> 26) as u32);
        g1 &= 0x3ffffff;
        let mut g3: u32 = h3.wrapping_add((g2 >> 26) as u32);
        g2 &= 0x3ffffff;
        let mut g4: u32 = h4.wrapping_add((g3 >> 26) as u32);
        g3 &= 0x3ffffff;
        g4 &= 0x3ffffff;

        // Select h if h < p, or h - p if h >= p
        // If g4 >= 4, then h >= p, so use g. Otherwise use h.
        let mask = ((g4 >> 2) as i32).wrapping_sub(1) as u32;
        let not_mask = !mask;
        
        h0 = (h0 & not_mask) | (g0 & mask);
        h1 = (h1 & not_mask) | (g1 & mask);
        h2 = (h2 & not_mask) | (g2 & mask);
        h3 = (h3 & not_mask) | (g3 & mask);
        h4 = (h4 & not_mask) | (g4 & mask);

        // h = h + s
        // First, convert h from radix 2^26 to a 128-bit integer
        let h_as_u128 = h0 as u128 + 
                       ((h1 as u128) << 26) + 
                       ((h2 as u128) << 52) + 
                       ((h3 as u128) << 78) + 
                       ((h4 as u128) << 104);
        
        // Convert s to 128-bit integer (little-endian)
        let s_as_u128 = self.s[0] as u128 + 
                       ((self.s[1] as u128) << 32) + 
                       ((self.s[2] as u128) << 64) + 
                       ((self.s[3] as u128) << 96);
        
        // Add s to h
        let final_h = h_as_u128.wrapping_add(s_as_u128);

        // Serialize final_h as a 128-bit little-endian integer
        let mut tag = [0u8; POLY1305_TAG_SIZE];
        tag[0..16].copy_from_slice(&final_h.to_le_bytes());

        tag
    }
}

/// Compute Poly1305 MAC for a message with the given key
pub fn poly1305_mac(msg: &[u8], key: &Poly1305Key) -> [u8; POLY1305_TAG_SIZE] {
    let mut state = Poly1305State::new(key);
    state.update(msg);
    state.finalize()
}

/// Verify a Poly1305 MAC
pub fn poly1305_verify(tag: &[u8], msg: &[u8], key: &Poly1305Key) -> bool {
    if tag.len() != POLY1305_TAG_SIZE {
        return false;
    }

    let computed_tag = poly1305_mac(msg, key);
    
    // Constant-time comparison
    let mut diff = 0;
    for i in 0..POLY1305_TAG_SIZE {
        diff |= tag[i] ^ computed_tag[i];
    }
    
    diff == 0
} 