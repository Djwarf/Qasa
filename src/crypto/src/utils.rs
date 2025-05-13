use rand::{rngs::OsRng, RngCore};

use crate::error::CryptoError;

/// Generate random bytes of the specified length
pub fn random_bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Constant-time comparison of two byte slices to avoid timing attacks
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Securely zero out sensitive data from memory
pub fn secure_zero(data: &mut [u8]) {
    // This is a simple implementation; in a production system,
    // we might use a more sophisticated approach or a dedicated crate
    for byte in data.iter_mut() {
        *byte = 0;
    }
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
}
