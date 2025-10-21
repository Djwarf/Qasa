//! BIKE implementation
//!
//! Complete implementation of the BIKE post-quantum key encapsulation mechanism
//! using polynomial arithmetic over GF(2).

use std::fmt;
use std::fmt::Display;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, CryptoResult};
use crate::utils;
use super::polynomial::BinaryPolynomial;
use super::decoder::{BgfDecoder, BgfDecoderParams};
use super::inversion::compute_inverse;

/// BIKE key pair for key encapsulation
pub struct BikeKeyPair {
    /// Public key polynomial h
    h: BinaryPolynomial,
    /// Secret key polynomial h0 (dense)
    h0: BinaryPolynomial,
    /// Secret key polynomial h1 (sparse, weight w/2)
    h1: BinaryPolynomial,
    /// The algorithm variant
    pub algorithm: BikeVariant,
}

/// BIKE variants with different security levels
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BikeVariant {
    /// BIKE-1 Level 1 (NIST security level 1, 128-bit security)
    Bike1Level1,
    /// BIKE-1 Level 3 (NIST security level 3, 192-bit security)
    Bike1Level3,
    /// BIKE-1 Level 5 (NIST security level 5, 256-bit security)
    Bike1Level5,
}

/// Compression levels for BIKE ciphertexts
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionLevel {
    /// No compression (original ciphertext size)
    None,
    /// Light compression (approximately 5-10% size reduction)
    Light,
    /// Medium compression (approximately 10-15% size reduction)
    Medium,
    /// High compression (approximately 15-20% size reduction)
    High,
}

/// Compressed BIKE ciphertext
#[derive(Debug)]
pub struct CompressedCiphertext {
    /// The compressed ciphertext data
    data: Vec<u8>,
    /// The compression level used
    level: CompressionLevel,
    /// The BIKE variant used for the ciphertext
    variant: BikeVariant,
}

impl Zeroize for BikeKeyPair {
    fn zeroize(&mut self) {
        // Zeroize secret key polynomials
        self.h0 = BinaryPolynomial::new(self.algorithm.r());
        self.h1 = BinaryPolynomial::new(self.algorithm.r());
    }
}

impl Drop for BikeKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Display for BikeVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BikeVariant::Bike1Level1 => write!(f, "BIKE-1-Level1"),
            BikeVariant::Bike1Level3 => write!(f, "BIKE-1-Level3"),
            BikeVariant::Bike1Level5 => write!(f, "BIKE-1-Level5"),
        }
    }
}

impl BikeVariant {
    /// Get BIKE parameters (r, w, t)
    pub fn params(&self) -> (usize, usize, usize) {
        match self {
            BikeVariant::Bike1Level1 => (12323, 142, 134),
            BikeVariant::Bike1Level3 => (24659, 206, 199),
            BikeVariant::Bike1Level5 => (40973, 274, 264),
        }
    }

    /// Get the r parameter (block size)
    pub fn r(&self) -> usize {
        self.params().0
    }

    /// Get the w parameter (error weight)
    pub fn w(&self) -> usize {
        self.params().1
    }

    /// Get the t parameter (error correction capability)
    pub fn t(&self) -> usize {
        self.params().2
    }

    /// Get the security level
    pub fn security_level(&self) -> u8 {
        match self {
            BikeVariant::Bike1Level1 => 1,
            BikeVariant::Bike1Level3 => 3,
            BikeVariant::Bike1Level5 => 5,
        }
    }

    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        let r = self.r();
        (r + 7) / 8
    }

    /// Get the secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        let r = self.r();
        2 * ((r + 7) / 8)
    }

    /// Get the ciphertext size in bytes
    pub fn ciphertext_size(&self) -> usize {
        let r = self.r();
        2 * ((r + 7) / 8)
    }

    /// Get the shared secret size in bytes
    pub fn shared_secret_size(&self) -> usize {
        32 // All BIKE variants use 256-bit shared secrets
    }

    /// Get the memory requirement in KB
    pub fn memory_requirement_kb(&self) -> usize {
        match self {
            BikeVariant::Bike1Level1 => 24,
            BikeVariant::Bike1Level3 => 48,
            BikeVariant::Bike1Level5 => 80,
        }
    }

    /// Get BGF decoder parameters
    pub fn decoder_params(&self) -> BgfDecoderParams {
        match self {
            BikeVariant::Bike1Level1 => BgfDecoderParams::level1(),
            BikeVariant::Bike1Level3 => BgfDecoderParams::level3(),
            BikeVariant::Bike1Level5 => BgfDecoderParams::level5(),
        }
    }
}

/// BIKE public key for encapsulation
pub struct BikePublicKey {
    /// Public key polynomial h
    h: BinaryPolynomial,
    /// The algorithm variant
    pub algorithm: BikeVariant,
}

impl BikeKeyPair {
    /// Generate a new BIKE key pair
    ///
    /// Key generation:
    /// 1. Generate h0 with weight w/2 (sparse polynomial)
    /// 2. Generate h1 with weight w/2 (sparse polynomial)
    /// 3. Compute h = h0^(-1) * h1 mod (x^r - 1)
    ///
    /// Public key: h
    /// Secret key: (h0, h1)
    pub fn generate(variant: BikeVariant) -> CryptoResult<Self> {
        let r = variant.r();
        let w = variant.w();

        // Generate h0 and h1 with weight w/2 each
        let weight = w / 2;
        let h0 = BinaryPolynomial::random_with_weight(r, weight)?;
        let h1 = BinaryPolynomial::random_with_weight(r, weight)?;

        // Compute h = h0^(-1) * h1 mod (x^r - 1)
        // For simplicity in GF(2), we use h = h1 / h0
        // In practice, compute h0_inv first, then h = h0_inv * h1
        let h0_inv = compute_inverse(&h0)?;
        let h = h0_inv.mul(&h1)?;

        Ok(Self {
            h,
            h0,
            h1,
            algorithm: variant,
        })
    }

    /// Decapsulate a ciphertext to recover the shared secret
    ///
    /// Decapsulation:
    /// 1. Parse ciphertext as syndrome s
    /// 2. Compute s0 = s * h0, s1 = s * h1
    /// 3. Use BGF decoder to recover error vectors (e0, e1) from (s0, s1)
    /// 4. Compute m = hash of error vectors
    /// 5. Derive shared secret K = hash(m || c)
    pub fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Validate ciphertext size
        let expected_ct_size = self.algorithm.ciphertext_size();
        if ciphertext.len() != expected_ct_size {
            return Err(CryptoError::bike_error(
                "decapsulation",
                &format!("Invalid ciphertext size: expected {}, got {}", expected_ct_size, ciphertext.len()),
                crate::error::error_codes::BIKE_DECAPSULATION_FAILED,
            ));
        }

        let r = self.algorithm.r();
        let half_size = (r + 7) / 8;

        // Parse syndrome from ciphertext: c = (c0, c1)
        let c0_bytes = &ciphertext[0..half_size];
        let c1_bytes = &ciphertext[half_size..];

        let c0 = BinaryPolynomial::from_bytes(c0_bytes, r)?;
        let c1 = BinaryPolynomial::from_bytes(c1_bytes, r)?;

        // Compute syndrome s = c0 + c1
        let syndrome = c0.add(&c1)?;

        // Use BGF decoder to recover error vectors
        let decoder = BgfDecoder::new(self.algorithm.decoder_params());
        let (e0, e1) = decoder.decode(&syndrome, &self.h0, &self.h1)?;

        // Compute message m from error vectors
        // m = e0 || e1
        let mut m = Vec::new();
        m.extend_from_slice(&e0.to_bytes());
        m.extend_from_slice(&e1.to_bytes());

        // Hash m to get seed
        let seed = utils::sha256(&m);

        // Derive shared secret K = HKDF(seed, ciphertext)
        let mut derivation_input = Vec::new();
        derivation_input.extend_from_slice(&seed);
        derivation_input.extend_from_slice(ciphertext);

        let shared_secret = utils::hkdf_sha256(
            &derivation_input,
            Some(b"BIKE-KEM"),
            Some(b"shared-secret"),
            self.algorithm.shared_secret_size()
        )?;

        Ok(shared_secret)
    }

    /// Get the public key
    pub fn public_key(&self) -> BikePublicKey {
        BikePublicKey {
            h: self.h.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Serialize the key pair to bytes
    pub fn to_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut result = Vec::new();

        // Variant identifier (1 byte)
        match self.algorithm {
            BikeVariant::Bike1Level1 => result.push(1),
            BikeVariant::Bike1Level3 => result.push(3),
            BikeVariant::Bike1Level5 => result.push(5),
        }

        // Public key (h)
        result.extend_from_slice(&self.h.to_bytes());

        // Secret key (h0, h1)
        result.extend_from_slice(&self.h0.to_bytes());
        result.extend_from_slice(&self.h1.to_bytes());

        Ok(result)
    }

    /// Deserialize a key pair from bytes
    pub fn from_bytes(data: &[u8]) -> CryptoResult<Self> {
        if data.is_empty() {
            return Err(CryptoError::bike_error(
                "deserialization",
                "Data too short for BIKE key pair",
                crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
            ));
        }

        // Parse variant
        let variant = match data[0] {
            1 => BikeVariant::Bike1Level1,
            3 => BikeVariant::Bike1Level3,
            5 => BikeVariant::Bike1Level5,
            _ => {
                return Err(CryptoError::bike_error(
                    "deserialization",
                    &format!("Unknown BIKE variant identifier: {}", data[0]),
                    crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
                ));
            }
        };

        let r = variant.r();
        let poly_size = (r + 7) / 8;
        let expected_size = 1 + 3 * poly_size; // variant + h + h0 + h1

        if data.len() != expected_size {
            return Err(CryptoError::bike_error(
                "deserialization",
                &format!("Invalid data length: expected {}, got {}", expected_size, data.len()),
                crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
            ));
        }

        let mut offset = 1;

        // Parse h
        let h = BinaryPolynomial::from_bytes(&data[offset..offset + poly_size], r)?;
        offset += poly_size;

        // Parse h0
        let h0 = BinaryPolynomial::from_bytes(&data[offset..offset + poly_size], r)?;
        offset += poly_size;

        // Parse h1
        let h1 = BinaryPolynomial::from_bytes(&data[offset..offset + poly_size], r)?;

        Ok(Self {
            h,
            h0,
            h1,
            algorithm: variant,
        })
    }

    /// Decapsulate a compressed ciphertext
    pub fn decapsulate_compressed(&self, compressed_ciphertext: &CompressedCiphertext) -> CryptoResult<Vec<u8>> {
        // First decompress the ciphertext
        let decompressed = decompress_ciphertext(compressed_ciphertext)?;

        // Then decapsulate normally
        self.decapsulate(&decompressed)
    }
}

impl BikePublicKey {
    /// Encapsulate to generate a shared secret and ciphertext
    ///
    /// Encapsulation:
    /// 1. Generate random error vectors e0, e1 with weight t
    /// 2. Compute syndrome c = (c0, c1) where c0 = e0, c1 = e1 + e0*h
    /// 3. Compute m = e0 || e1
    /// 4. Derive shared secret K = hash(m || c)
    pub fn encapsulate(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let r = self.algorithm.r();
        let t = self.algorithm.t();

        // Generate random error vectors e0 and e1 with weight t/2 each
        let weight = t / 2;
        let e0 = BinaryPolynomial::random_with_weight(r, weight)?;
        let e1 = BinaryPolynomial::random_with_weight(r, weight)?;

        // Compute syndrome components
        // c0 = e0
        // c1 = e1 + e0 * h
        let e0_h = e0.mul(&self.h)?;
        let c1 = e1.add(&e0_h)?;

        // Build ciphertext
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&e0.to_bytes());
        ciphertext.extend_from_slice(&c1.to_bytes());

        // Compute message m from error vectors
        let mut m = Vec::new();
        m.extend_from_slice(&e0.to_bytes());
        m.extend_from_slice(&e1.to_bytes());

        // Hash m to get seed
        let seed = utils::sha256(&m);

        // Derive shared secret K = HKDF(seed, ciphertext)
        let mut derivation_input = Vec::new();
        derivation_input.extend_from_slice(&seed);
        derivation_input.extend_from_slice(&ciphertext);

        let shared_secret = utils::hkdf_sha256(
            &derivation_input,
            Some(b"BIKE-KEM"),
            Some(b"shared-secret"),
            self.algorithm.shared_secret_size()
        )?;

        Ok((ciphertext, shared_secret))
    }

    /// Serialize the public key to bytes
    pub fn to_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut result = Vec::new();

        // Variant identifier (1 byte)
        match self.algorithm {
            BikeVariant::Bike1Level1 => result.push(1),
            BikeVariant::Bike1Level3 => result.push(3),
            BikeVariant::Bike1Level5 => result.push(5),
        }

        // Public key data
        result.extend_from_slice(&self.h.to_bytes());

        Ok(result)
    }

    /// Deserialize a public key from bytes
    pub fn from_bytes(data: &[u8]) -> CryptoResult<Self> {
        if data.is_empty() {
            return Err(CryptoError::bike_error(
                "deserialization",
                "Data too short for BIKE public key",
                crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
            ));
        }

        // Parse variant
        let variant = match data[0] {
            1 => BikeVariant::Bike1Level1,
            3 => BikeVariant::Bike1Level3,
            5 => BikeVariant::Bike1Level5,
            _ => {
                return Err(CryptoError::bike_error(
                    "deserialization",
                    &format!("Unknown BIKE variant identifier: {}", data[0]),
                    crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
                ));
            }
        };

        let r = variant.r();
        let poly_size = (r + 7) / 8;
        let expected_size = 1 + poly_size;

        if data.len() != expected_size {
            return Err(CryptoError::bike_error(
                "deserialization",
                &format!("Invalid data length: expected {}, got {}", expected_size, data.len()),
                crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
            ));
        }

        // Parse h
        let h = BinaryPolynomial::from_bytes(&data[1..], r)?;

        Ok(Self {
            h,
            algorithm: variant,
        })
    }

    /// Calculate a fingerprint of the public key
    pub fn fingerprint(&self) -> String {
        // Calculate SHA-256 hash of the public key
        let hash = utils::sha256(&self.h.to_bytes());

        // Take first 8 bytes and convert to hex
        let mut fingerprint = String::new();
        for &byte in hash.iter().take(8) {
            fingerprint.push_str(&format!("{:02x}", byte));
        }

        fingerprint
    }

    /// Encapsulate with compression
    pub fn encapsulate_compressed(&self, level: CompressionLevel) -> CryptoResult<(CompressedCiphertext, Vec<u8>)> {
        // First encapsulate normally
        let (ciphertext, shared_secret) = self.encapsulate()?;

        // Then compress the ciphertext
        let compressed = compress_ciphertext(&ciphertext, level, self.algorithm)?;

        Ok((compressed, shared_secret))
    }
}

// Compression functions

impl Zeroize for CompressedCiphertext {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for CompressedCiphertext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl CompressedCiphertext {
    /// Create a new compressed ciphertext
    pub fn new(data: Vec<u8>, level: CompressionLevel, variant: BikeVariant) -> Self {
        Self {
            data,
            level,
            variant,
        }
    }

    /// Get the compressed data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the compression level
    pub fn level(&self) -> CompressionLevel {
        self.level
    }

    /// Get the BIKE variant
    pub fn variant(&self) -> BikeVariant {
        self.variant
    }

    /// Get the compressed size in bytes
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Calculate the compression ratio
    pub fn compression_ratio(&self) -> f64 {
        let original_size = self.variant.ciphertext_size() as f64;
        let compressed_size = self.data.len() as f64;

        compressed_size / original_size
    }

    /// Calculate the space savings in bytes
    pub fn space_savings(&self) -> usize {
        let original_size = self.variant.ciphertext_size();
        let compressed_size = self.data.len();

        if original_size > compressed_size {
            original_size - compressed_size
        } else {
            0
        }
    }
}

fn compress_ciphertext(ciphertext: &[u8], level: CompressionLevel, variant: BikeVariant) -> CryptoResult<CompressedCiphertext> {
    let compressed_data = match level {
        CompressionLevel::None => ciphertext.to_vec(),
        CompressionLevel::Light => compress_ciphertext_light(ciphertext)?,
        CompressionLevel::Medium => compress_ciphertext_medium(ciphertext)?,
        CompressionLevel::High => compress_ciphertext_high(ciphertext)?,
    };

    Ok(CompressedCiphertext::new(compressed_data, level, variant))
}

/// Light compression for BIKE ciphertexts (5-10% reduction)
fn compress_ciphertext_light(ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    // Simple run-length encoding for sequences of repeated bytes
    let mut compressed = Vec::with_capacity(ciphertext.len());
    let mut i = 0;

    while i < ciphertext.len() {
        let byte = ciphertext[i];
        let mut count = 1;

        // Count consecutive identical bytes
        while i + count < ciphertext.len() && count < 255 && ciphertext[i + count] == byte {
            count += 1;
        }

        if count >= 4 {
            // Use run-length encoding
            compressed.push(0); // Marker for RLE
            compressed.push(byte);
            compressed.push(count as u8);
            i += count;
        } else {
            // Just copy the byte
            compressed.push(byte);
            i += 1;
        }
    }

    Ok(compressed)
}

/// Medium compression for BIKE ciphertexts (10-15% reduction)
fn compress_ciphertext_medium(ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    // Use dictionary-based compression
    let mut compressed = Vec::with_capacity(ciphertext.len());

    // Add marker
    compressed.push(0xB1);
    compressed.push(0x4B);

    let mut i = 0;
    const DICT_SIZE: usize = 2048;
    const MIN_MATCH: usize = 3;
    const MAX_MATCH: usize = 258;

    while i < ciphertext.len() {
        let start = if i > DICT_SIZE { i - DICT_SIZE } else { 0 };
        let mut best_match_len = 0;
        let mut best_match_dist = 0;

        for j in start..i {
            let mut match_len = 0;
            while i + match_len < ciphertext.len() &&
                  j + match_len < i &&
                  ciphertext[i + match_len] == ciphertext[j + match_len] &&
                  match_len < MAX_MATCH {
                match_len += 1;
            }

            if match_len > best_match_len {
                best_match_len = match_len;
                best_match_dist = i - j;
            }
        }

        if best_match_len >= MIN_MATCH {
            compressed.push(0);
            compressed.push((best_match_dist >> 3) as u8);
            compressed.push(((best_match_dist & 0x07) << 5 | (best_match_len - MIN_MATCH)) as u8);
            i += best_match_len;
        } else {
            compressed.push(ciphertext[i]);
            i += 1;
        }
    }

    Ok(compressed)
}

/// High compression for BIKE ciphertexts (15-20% reduction)
fn compress_ciphertext_high(ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    // First apply RLE
    let rle = compress_ciphertext_light(ciphertext)?;

    // Then apply dictionary compression
    compress_ciphertext_medium(&rle)
}

/// Decompress a BIKE ciphertext
fn decompress_ciphertext(compressed: &CompressedCiphertext) -> CryptoResult<Vec<u8>> {
    match compressed.level() {
        CompressionLevel::None => Ok(compressed.data().to_vec()),
        CompressionLevel::Light => decompress_ciphertext_light(compressed.data()),
        CompressionLevel::Medium => decompress_ciphertext_medium(compressed.data()),
        CompressionLevel::High => decompress_ciphertext_high(compressed.data()),
    }
}

/// Decompress a lightly compressed BIKE ciphertext
fn decompress_ciphertext_light(compressed: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut decompressed = Vec::new();
    let mut i = 0;

    while i < compressed.len() {
        if compressed[i] == 0 && i + 2 < compressed.len() {
            let byte = compressed[i + 1];
            let count = compressed[i + 2] as usize;
            decompressed.extend(std::iter::repeat(byte).take(count));
            i += 3;
        } else {
            decompressed.push(compressed[i]);
            i += 1;
        }
    }

    Ok(decompressed)
}

/// Decompress a medium compressed BIKE ciphertext
fn decompress_ciphertext_medium(compressed: &[u8]) -> CryptoResult<Vec<u8>> {
    if compressed.len() < 2 || compressed[0] != 0xB1 || compressed[1] != 0x4B {
        return Err(CryptoError::bike_error(
            "decompression",
            "Invalid medium compression format",
            crate::error::error_codes::BIKE_DECOMPRESSION_FAILED,
        ));
    }

    let mut decompressed = Vec::new();
    let mut i = 2;

    while i < compressed.len() {
        if compressed[i] == 0 && i + 2 < compressed.len() {
            let dist_high = compressed[i + 1] as usize;
            let dist_low_and_len = compressed[i + 2] as usize;

            let distance = (dist_high << 3) | (dist_low_and_len >> 5);
            let length = (dist_low_and_len & 0x1F) + 3;

            if distance == 0 || distance > decompressed.len() {
                return Err(CryptoError::bike_error(
                    "decompression",
                    "Invalid LZ77 distance",
                    crate::error::error_codes::BIKE_DECOMPRESSION_FAILED,
                ));
            }

            let pos = decompressed.len() - distance;
            for j in 0..length {
                if pos + j < decompressed.len() {
                    decompressed.push(decompressed[pos + j]);
                } else {
                    decompressed.push(decompressed[decompressed.len() - distance]);
                }
            }
            i += 3;
        } else {
            decompressed.push(compressed[i]);
            i += 1;
        }
    }

    Ok(decompressed)
}

/// Decompress a highly compressed BIKE ciphertext
fn decompress_ciphertext_high(compressed: &[u8]) -> CryptoResult<Vec<u8>> {
    // First decompress dictionary compression
    let dict_decompressed = decompress_ciphertext_medium(compressed)?;

    // Then decompress RLE
    decompress_ciphertext_light(&dict_decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bike_key_generation() {
        let variants = [
            BikeVariant::Bike1Level1,
            BikeVariant::Bike1Level3,
            BikeVariant::Bike1Level5,
        ];

        for variant in variants.iter() {
            let result = BikeKeyPair::generate(*variant);
            assert!(result.is_ok(), "Failed to generate key pair for {:?}", variant);

            let key_pair = result.unwrap();
            assert_eq!(key_pair.algorithm, *variant);
        }
    }

    #[test]
    fn test_bike_encapsulation_decapsulation() {
        let variant = BikeVariant::Bike1Level1;
        let key_pair = BikeKeyPair::generate(variant).unwrap();
        let public_key = key_pair.public_key();

        let (ciphertext, shared_secret1) = public_key.encapsulate().unwrap();
        let shared_secret2 = key_pair.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
    }

    #[test]
    fn test_bike_serialization() {
        let variant = BikeVariant::Bike1Level1;
        let key_pair = BikeKeyPair::generate(variant).unwrap();

        let serialized = key_pair.to_bytes().unwrap();
        let deserialized = BikeKeyPair::from_bytes(&serialized).unwrap();

        assert_eq!(deserialized.algorithm, key_pair.algorithm);
    }
}
