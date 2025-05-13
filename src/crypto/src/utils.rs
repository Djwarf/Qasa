use rand::{rngs::OsRng, RngCore};
use std::ptr;
use zeroize::Zeroize;

use crate::error::CryptoError;

/// Generate random bytes of the specified length
pub fn random_bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Constant-time comparison of two byte slices to avoid timing attacks
///
/// This function compares two byte slices in constant time to prevent
/// timing attacks that could leak information about the content.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // This is more idiomatic and still constant-time
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Securely zero out sensitive data from memory
///
/// This function uses the zeroize crate to ensure the data is properly
/// zeroed and not optimized away by the compiler.
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

/// Convert bytes to a hexadecimal string
pub fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert a hexadecimal string to bytes
pub fn from_hex(hex: &str) -> Result<Vec<u8>, CryptoError> {
    if hex.len() % 2 != 0 {
        return Err(CryptoError::InvalidParameterError(
            "Hex string must have an even number of characters".to_string(),
        ));
    }

    let mut result = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).map_err(|_| {
            CryptoError::InvalidParameterError(format!("Invalid hex character: {}", byte_str))
        })?;
        result.push(byte);
    }

    Ok(result)
}

/// Securely compare two potentially sensitive strings in constant time
///
/// This is useful for comparing passwords, tokens, or other sensitive strings
/// where timing attacks could be a concern.
pub fn secure_compare(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Concatenate multiple byte slices efficiently
pub fn concat_bytes(slices: &[&[u8]]) -> Vec<u8> {
    let total_len = slices.iter().map(|s| s.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for slice in slices {
        result.extend_from_slice(slice);
    }
    result
}

/// Copy bytes from source to destination
///
/// This is a safe wrapper around ptr::copy_nonoverlapping for when
/// you need to copy bytes between slices.
///
/// # Arguments
///
/// * `src` - Source byte slice
/// * `dst` - Destination byte slice
///
/// # Returns
///
/// `Ok(())` if successful, or an error if dst is not large enough
pub fn copy_bytes(src: &[u8], dst: &mut [u8]) -> Result<(), CryptoError> {
    if dst.len() < src.len() {
        return Err(CryptoError::InvalidParameterError(
            "Destination buffer too small".to_string(),
        ));
    }

    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
    }

    Ok(())
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
}
