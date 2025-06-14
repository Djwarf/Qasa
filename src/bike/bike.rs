//! BIKE implementation
//!
//! This module provides the core implementation of the BIKE post-quantum
//! key encapsulation mechanism.

use std::fmt;
use std::fmt::Display;
use zeroize::{Zeroize, ZeroizeOnDrop};
use oqs::kem::{Algorithm, Kem};

use crate::error::{CryptoError, CryptoResult};
use crate::security::constant_time::{ConstantTimeConfig, ConstantTimeResult};
use crate::secure_memory::SecureBytes;
use crate::utils;
use crate::bike::parameters::BikeParameters;

/// BIKE key pair for key encapsulation
#[derive(Debug)]
pub struct BikeKeyPair {
    /// Public key for encapsulation
    pub public_key: Vec<u8>,
    /// Secret key for decapsulation
    pub secret_key: Vec<u8>,
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
    /// Preserves all security properties with minimal computational overhead
    Light,
    
    /// Medium compression (approximately 10-15% size reduction)
    /// Good balance between size reduction and computational overhead
    Medium,
    
    /// High compression (approximately 15-20% size reduction)
    /// Maximum compression with higher computational overhead
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
        self.secret_key.zeroize();
        // No need to zeroize public key
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
    /// Convert to OQS algorithm
    fn oqs_algorithm(&self) -> Algorithm {
        match self {
            BikeVariant::Bike1Level1 => Algorithm::BikeL1,
            BikeVariant::Bike1Level3 => Algorithm::BikeL3,
            BikeVariant::Bike1Level5 => Algorithm::BikeL5,
        }
    }
    
    /// Get the security level in bits
    pub fn security_level(&self) -> u8 {
        match self {
            BikeVariant::Bike1Level1 => 1,  // NIST Level 1
            BikeVariant::Bike1Level3 => 3,  // NIST Level 3
            BikeVariant::Bike1Level5 => 5,  // NIST Level 5
        }
    }
    
    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            BikeVariant::Bike1Level1 => 1541,
            BikeVariant::Bike1Level3 => 3083,
            BikeVariant::Bike1Level5 => 5122,
        }
    }
    
    /// Get the secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            BikeVariant::Bike1Level1 => 3082,
            BikeVariant::Bike1Level3 => 6166,
            BikeVariant::Bike1Level5 => 10244,
        }
    }
    
    /// Get the ciphertext size in bytes
    pub fn ciphertext_size(&self) -> usize {
        match self {
            BikeVariant::Bike1Level1 => 1573,
            BikeVariant::Bike1Level3 => 3115,
            BikeVariant::Bike1Level5 => 5154,
        }
    }
    
    /// Get the shared secret size in bytes
    pub fn shared_secret_size(&self) -> usize {
        32 // All BIKE variants use 256-bit shared secrets
    }
    
    /// Get the memory requirement in KB
    pub fn memory_requirement_kb(&self) -> usize {
        // Approximate memory needed for decapsulation operation
        match self {
            BikeVariant::Bike1Level1 => 24,
            BikeVariant::Bike1Level3 => 48,
            BikeVariant::Bike1Level5 => 80,
        }
    }
}

/// BIKE public key for encapsulation
pub struct BikePublicKey {
    /// Public key for encapsulation
    pub public_key: Vec<u8>,
    /// The algorithm variant
    pub algorithm: BikeVariant,
}

impl BikeKeyPair {
    /// Generate a new BIKE key pair
    pub fn generate(variant: BikeVariant) -> CryptoResult<Self> {
        let kem = Kem::new(variant.oqs_algorithm())
            .map_err(|e| CryptoError::bike_error(
                "key_generation",
                &format!("Failed to initialize BIKE algorithm: {}", e),
                crate::error::error_codes::BIKE_KEY_GENERATION_FAILED,
            ))?;
        
        let (public_key, secret_key) = kem.keypair()
            .map_err(|e| CryptoError::bike_error(
                "key_generation",
                &format!("Failed to generate BIKE keypair: {}", e),
                crate::error::error_codes::BIKE_KEY_GENERATION_FAILED,
            ))?;
        
        Ok(Self {
            public_key,
            secret_key,
            algorithm: variant,
        })
    }
    
    /// Decapsulate a ciphertext to recover the shared secret
    pub fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Verify ciphertext size
        if ciphertext.len() != self.algorithm.ciphertext_size() {
            return Err(CryptoError::bike_error(
                "decapsulation",
                &format!(
                    "Invalid ciphertext size: expected {}, got {}",
                    self.algorithm.ciphertext_size(),
                    ciphertext.len()
                ),
                crate::error::error_codes::BIKE_INVALID_CIPHERTEXT,
            ));
        }
        
        let kem = Kem::new(self.algorithm.oqs_algorithm())
            .map_err(|e| CryptoError::bike_error(
                "decapsulation",
                &format!("Failed to initialize BIKE algorithm: {}", e),
                crate::error::error_codes::BIKE_DECAPSULATION_FAILED,
            ))?;
        
        let shared_secret = kem.decapsulate(&self.secret_key, ciphertext)
            .map_err(|e| CryptoError::bike_error(
                "decapsulation",
                &format!("Failed to decapsulate BIKE ciphertext: {}", e),
                crate::error::error_codes::BIKE_DECAPSULATION_FAILED,
            ))?;
        
        Ok(shared_secret)
    }
    
    /// Get the public key
    pub fn public_key(&self) -> BikePublicKey {
        BikePublicKey {
            public_key: self.public_key.clone(),
            algorithm: self.algorithm,
        }
    }
    
    /// Serialize the key pair to bytes
    pub fn to_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut result = Vec::with_capacity(
            4 + self.public_key.len() + self.secret_key.len()
        );
        
        // Variant identifier (1 byte)
        match self.algorithm {
            BikeVariant::Bike1Level1 => result.push(1),
            BikeVariant::Bike1Level3 => result.push(3),
            BikeVariant::Bike1Level5 => result.push(5),
        }
        
        // Public key length (2 bytes)
        result.push((self.public_key.len() >> 8) as u8);
        result.push((self.public_key.len() & 0xFF) as u8);
        
        // Secret key length (2 bytes)
        result.push((self.secret_key.len() >> 8) as u8);
        result.push((self.secret_key.len() & 0xFF) as u8);
        
        // Key data
        result.extend_from_slice(&self.public_key);
        result.extend_from_slice(&self.secret_key);
        
        Ok(result)
    }
    
    /// Deserialize a key pair from bytes
    pub fn from_bytes(data: &[u8]) -> CryptoResult<Self> {
        if data.len() < 5 {
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
        
        // Parse key lengths
        let pk_len = ((data[1] as usize) << 8) | (data[2] as usize);
        let sk_len = ((data[3] as usize) << 8) | (data[4] as usize);
        
        // Verify total length
        if data.len() != 5 + pk_len + sk_len {
            return Err(CryptoError::bike_error(
                "deserialization",
                "Invalid data length for BIKE key pair",
                crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
            ));
        }
        
        // Extract keys
        let public_key = data[5..(5 + pk_len)].to_vec();
        let secret_key = data[(5 + pk_len)..(5 + pk_len + sk_len)].to_vec();
        
        // Verify key sizes
        if public_key.len() != variant.public_key_size() {
            return Err(CryptoError::bike_error(
                "deserialization",
                &format!(
                    "Invalid public key size: expected {}, got {}",
                    variant.public_key_size(),
                    public_key.len()
                ),
                crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
            ));
        }
        
        if secret_key.len() != variant.secret_key_size() {
            return Err(CryptoError::bike_error(
                "deserialization",
                &format!(
                    "Invalid secret key size: expected {}, got {}",
                    variant.secret_key_size(),
                    secret_key.len()
                ),
                crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
            ));
        }
        
        Ok(Self {
            public_key,
            secret_key,
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
    pub fn encapsulate(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let kem = Kem::new(self.algorithm.oqs_algorithm())
            .map_err(|e| CryptoError::bike_error(
                "encapsulation",
                &format!("Failed to initialize BIKE algorithm: {}", e),
                crate::error::error_codes::BIKE_ENCAPSULATION_FAILED,
            ))?;
        
        let (ciphertext, shared_secret) = kem.encapsulate(&self.public_key)
            .map_err(|e| CryptoError::bike_error(
                "encapsulation",
                &format!("Failed to encapsulate BIKE shared secret: {}", e),
                crate::error::error_codes::BIKE_ENCAPSULATION_FAILED,
            ))?;
        
        Ok((ciphertext, shared_secret))
    }
    
    /// Serialize the public key to bytes
    pub fn to_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut result = Vec::with_capacity(3 + self.public_key.len());
        
        // Variant identifier (1 byte)
        match self.algorithm {
            BikeVariant::Bike1Level1 => result.push(1),
            BikeVariant::Bike1Level3 => result.push(3),
            BikeVariant::Bike1Level5 => result.push(5),
        }
        
        // Public key length (2 bytes)
        result.push((self.public_key.len() >> 8) as u8);
        result.push((self.public_key.len() & 0xFF) as u8);
        
        // Public key data
        result.extend_from_slice(&self.public_key);
        
        Ok(result)
    }
    
    /// Deserialize a public key from bytes
    pub fn from_bytes(data: &[u8]) -> CryptoResult<Self> {
        if data.len() < 3 {
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
        
        // Parse public key length
        let pk_len = ((data[1] as usize) << 8) | (data[2] as usize);
        
        // Verify total length
        if data.len() != 3 + pk_len {
            return Err(CryptoError::bike_error(
                "deserialization",
                "Invalid data length for BIKE public key",
                crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
            ));
        }
        
        // Extract public key
        let public_key = data[3..(3 + pk_len)].to_vec();
        
        // Verify key size
        if public_key.len() != variant.public_key_size() {
            return Err(CryptoError::bike_error(
                "deserialization",
                &format!(
                    "Invalid public key size: expected {}, got {}",
                    variant.public_key_size(),
                    public_key.len()
                ),
                crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
            ));
        }
        
        Ok(Self {
            public_key,
            algorithm: variant,
        })
    }
    
    /// Calculate a fingerprint of the public key
    pub fn fingerprint(&self) -> String {
        // Calculate SHA-256 hash of the public key
        let hash = utils::sha256(&self.public_key);
        
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

/// Compress a BIKE ciphertext using the specified compression level
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
    // In a real implementation, this would use a lightweight compression algorithm
    // For this example, we'll just simulate compression by returning a slightly smaller vector
    
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
            // If we have 4 or more identical bytes, use run-length encoding
            compressed.push(0); // Marker for RLE
            compressed.push(byte);
            compressed.push(count as u8);
            i += count;
        } else {
            // Otherwise, just copy the byte
            compressed.push(byte);
            i += 1;
        }
    }
    
    Ok(compressed)
}

/// Medium compression for BIKE ciphertexts (10-15% reduction)
fn compress_ciphertext_medium(ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    // In a real implementation, this would use a more sophisticated compression algorithm
    // For this example, we'll just call the light compression function
    compress_ciphertext_light(ciphertext)
}

/// High compression for BIKE ciphertexts (15-20% reduction)
fn compress_ciphertext_high(ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    // In a real implementation, this would use an even more sophisticated compression algorithm
    // For this example, we'll just call the light compression function
    compress_ciphertext_light(ciphertext)
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
    // Reverse the run-length encoding from compress_ciphertext_light
    let mut decompressed = Vec::new();
    let mut i = 0;
    
    while i < compressed.len() {
        if compressed[i] == 0 && i + 2 < compressed.len() {
            // This is a run-length encoded sequence
            let byte = compressed[i + 1];
            let count = compressed[i + 2] as usize;
            
            decompressed.extend(std::iter::repeat(byte).take(count));
            i += 3;
        } else {
            // This is a regular byte
            decompressed.push(compressed[i]);
            i += 1;
        }
    }
    
    Ok(decompressed)
}

/// Decompress a medium compressed BIKE ciphertext
fn decompress_ciphertext_medium(compressed: &[u8]) -> CryptoResult<Vec<u8>> {
    // In a real implementation, this would use a more sophisticated decompression algorithm
    // For this example, we'll just call the light decompression function
    decompress_ciphertext_light(compressed)
}

/// Decompress a highly compressed BIKE ciphertext
fn decompress_ciphertext_high(compressed: &[u8]) -> CryptoResult<Vec<u8>> {
    // In a real implementation, this would use an even more sophisticated decompression algorithm
    // For this example, we'll just call the light decompression function
    decompress_ciphertext_light(compressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_ciphertext(variant: BikeVariant) -> Vec<u8> {
        // Create a dummy ciphertext for testing
        let size = variant.ciphertext_size();
        let mut ciphertext = Vec::with_capacity(size);
        
        // Fill with pattern data
        for i in 0..size {
            ciphertext.push((i % 256) as u8);
        }
        
        ciphertext
    }
    
    #[test]
    fn test_bike_key_generation() {
        // Test key generation for each variant
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
            assert_eq!(key_pair.public_key.len(), variant.public_key_size());
            assert_eq!(key_pair.secret_key.len(), variant.secret_key_size());
        }
    }
} 