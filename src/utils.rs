use rand::{rngs::OsRng, RngCore};
use std::ptr;
use zeroize::Zeroize;

use crate::error::CryptoError;

/// Generate cryptographically secure random bytes of the specified length
///
/// This function uses the operating system's secure random number generator (OsRng)
/// to generate cryptographically secure random bytes. It's suitable for generating
/// keys, nonces, initialization vectors, and other cryptographic material.
///
/// # Arguments
///
/// * `length` - The number of random bytes to generate
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - A vector containing the random bytes
/// * `Err(CryptoError)` - If random generation fails
///
/// # Security Considerations
///
/// This function relies on the OS's entropy source, which should be secure for
/// cryptographic purposes. The resulting bytes are suitable for sensitive
/// cryptographic operations.
pub fn random_bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Perform constant-time comparison of two byte slices to prevent timing attacks
///
/// This function compares two byte slices in constant time, meaning the time taken
/// to perform the comparison is independent of the content of the slices.
/// This helps prevent timing attacks that could extract secrets by measuring
/// small differences in execution time.
///
/// # Arguments
///
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
///
/// * `true` if the slices are equal
/// * `false` if the slices differ in length or content
///
/// # Security Considerations
///
/// This function is designed to be resistant to timing attacks by using the
/// subtle crate's constant-time comparison functions. It should be used when
/// comparing sensitive data like MACs, signatures, or other values where
/// timing information could leak secrets.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // This is more idiomatic and still constant-time
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Securely erase sensitive data from memory
///
/// This function securely zeroes out sensitive data, ensuring that the zeroing
/// operation is not optimized away by the compiler. This is crucial for sensitive
/// information like cryptographic keys that should be removed from memory once
/// they're no longer needed.
///
/// # Arguments
///
/// * `data` - Mutable slice of bytes to be zeroed
///
/// # Security Considerations
///
/// Uses the zeroize crate which implements secure zeroing that resists
/// compiler optimizations which might remove "unnecessary" memory writes.
/// This helps prevent secrets from being unintentionally left in memory.
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

/// Convert a byte array to a hexadecimal string representation
///
/// This function converts a byte slice to a lowercase hexadecimal string,
/// which is useful for debug output, log messages, or user display.
///
/// # Arguments
///
/// * `data` - The byte slice to convert
///
/// # Returns
///
/// A String containing the hexadecimal representation of the input bytes
pub fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert a hexadecimal string to a byte array
///
/// This function parses a hexadecimal string and converts it to the corresponding
/// bytes. It expects a valid hexadecimal string with an even number of characters.
///
/// # Arguments
///
/// * `hex` - The hexadecimal string to convert
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The parsed bytes
/// * `Err(CryptoError)` - If the string has an odd length or contains invalid characters
pub fn from_hex(hex: &str) -> Result<Vec<u8>, CryptoError> {
    if hex.len() % 2 != 0 {
        return Err(CryptoError::invalid_parameter(
            "hex_string",
            "even number of characters",
            &format!("{} characters", hex.len()),
        ));
    }

    let mut result = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).map_err(|_| {
            CryptoError::invalid_parameter(
                "hex_character",
                "valid hex digit (0-9, a-f, A-F)",
                byte_str,
            )
        })?;
        result.push(byte);
    }

    Ok(result)
}

/// Compare two strings in constant time to prevent timing attacks
///
/// This function is a specialized wrapper around constant_time_eq for string
/// comparisons. It's useful for comparing passwords, tokens, or other sensitive
/// string data where timing attacks could be a concern.
///
/// # Arguments
///
/// * `a` - First string
/// * `b` - Second string
///
/// # Returns
///
/// * `true` if the strings are equal
/// * `false` if the strings are different
///
/// # Security Considerations
///
/// This function ensures that the comparison time does not depend on the
/// content of the strings, which helps prevent timing attacks that could
/// extract sensitive information by measuring execution time differences.
pub fn secure_compare(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Efficiently concatenate multiple byte slices into a single vector
///
/// This function concatenates multiple byte slices into a single `Vec<u8>`,
/// pre-allocating the exact amount of memory needed to avoid reallocations.
///
/// # Arguments
///
/// * `slices` - Slice of byte slices to concatenate
///
/// # Returns
///
/// A `Vec<u8>` containing all input slices concatenated in order
pub fn concat_bytes(slices: &[&[u8]]) -> Vec<u8> {
    let total_len = slices.iter().map(|s| s.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for slice in slices {
        result.extend_from_slice(slice);
    }
    result
}

/// Safely copy bytes from one buffer to another using low-level memory operations
///
/// This function provides a safe wrapper around the unsafe ptr::copy_nonoverlapping
/// function, which allows for efficiently copying bytes between buffers. It performs
/// bounds checking to ensure memory safety.
///
/// # Arguments
///
/// * `src` - Source byte slice
/// * `dst` - Destination mutable byte slice
///
/// # Returns
///
/// * `Ok(())` if the copy was successful
/// * `Err(CryptoError)` if the destination buffer is too small to hold the source data
///
/// # Security Considerations
///
/// This function ensures safe memory operations by checking bounds before
/// performing the copy. The underlying implementation uses ptr::copy_nonoverlapping,
/// which is typically more efficient than a loop-based copy.
pub fn copy_bytes(src: &[u8], dst: &mut [u8]) -> Result<(), CryptoError> {
    if dst.len() < src.len() {
        return Err(CryptoError::invalid_parameter(
            "destination_buffer",
            &format!("{} bytes", src.len()),
            &format!("{} bytes", dst.len()),
        ));
    }

    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
    }

    Ok(())
}

/// Compute the SHA-256 hash of the input data
///
/// This function computes the SHA-256 cryptographic hash of the input data.
/// SHA-256 is a secure hash function that produces a 32-byte (256-bit) digest.
///
/// # Arguments
///
/// * `data` - The input data to hash
///
/// # Returns
///
/// A 32-byte vector containing the SHA-256 hash
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Perform HKDF key derivation using SHA-256
///
/// This function implements HKDF (HMAC-based Key Derivation Function) using SHA-256
/// as the underlying hash function. HKDF is used to derive one or more keys from
/// input key material in a secure way.
///
/// # Arguments
///
/// * `ikm` - Input key material
/// * `salt` - Optional salt value (can be empty)
/// * `info` - Optional context and application specific information (can be empty)
/// * `length` - Length of the output key material in bytes
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The derived key material of the requested length
/// * `Err(CryptoError)` - If key derivation fails
///
/// # Security Considerations
///
/// HKDF is suitable for deriving keys from high-entropy sources (like shared secrets
/// from key exchange) as well as from low-entropy sources (like passwords, when
/// combined with a proper password hashing function).
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, crate::error::CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    
    hkdf.expand(info, &mut okm)
        .map_err(|_| crate::error::CryptoError::key_management_error(
            "hkdf_expand",
            "HKDF expansion failed, requested output too long",
            "HKDF",
        ))?;
    
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        // Two random byte arrays should be different
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];
        let d = [1, 2, 3];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
    }

    #[test]
    fn test_secure_zero() {
        let mut data = [1, 2, 3, 4];
        secure_zero(&mut data);
        assert_eq!(data, [0, 0, 0, 0]);
    }

    #[test]
    fn test_hex_conversion() {
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = to_hex(&data);
        assert_eq!(hex, "0123456789abcdef");

        let bytes = from_hex(&hex).unwrap();
        assert_eq!(bytes, data);
    }

    #[test]
    fn test_secure_compare() {
        let a = "secure-password";
        let b = "secure-password";
        let c = "different-password";

        assert!(secure_compare(a, b));
        assert!(!secure_compare(a, c));
    }

    #[test]
    fn test_concat_bytes() {
        let a = [1, 2, 3];
        let b = [4, 5];
        let c = [6, 7, 8, 9];

        let result = concat_bytes(&[&a, &b, &c]);
        assert_eq!(result, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_copy_bytes() {
        let src = [1, 2, 3, 4];
        let mut dst = [0; 6];

        copy_bytes(&src, &mut dst).unwrap();
        assert_eq!(dst, [1, 2, 3, 4, 0, 0]);

        // Test error case with destination too small
        let mut small_dst = [0; 2];
        let result = copy_bytes(&src, &mut small_dst);
        assert!(result.is_err());
    }

    #[test]
    fn test_sha256() {
        let data = b"test data for hashing";
        let hash = sha256(data);
        
        // SHA-256 always produces a 32-byte output
        assert_eq!(hash.len(), 32);
        
        // Verify deterministic output
        let hash2 = sha256(data);
        assert_eq!(hash, hash2);
        
        // Verify different input produces different output
        let hash3 = sha256(b"different data");
        assert_ne!(hash, hash3);
    }
    
    #[test]
    fn test_hkdf_sha256() {
        let ikm = b"input key material";
        let salt = b"salt value";
        let info = b"context info";
        
        let key1 = hkdf_sha256(ikm, salt, info, 32).unwrap();
        let key2 = hkdf_sha256(ikm, salt, info, 32).unwrap();
        
        // Verify deterministic output
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
        
        // Verify different parameters produce different output
        let key3 = hkdf_sha256(ikm, b"different salt", info, 32).unwrap();
        assert_ne!(key1, key3);
        
        // Verify different length output
        let key4 = hkdf_sha256(ikm, salt, info, 64).unwrap();
        assert_eq!(key4.len(), 64);
    }
}
