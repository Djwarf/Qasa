// Password handling implementation
// This file contains code moved from src/key_management.rs for password handling

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, ParamsBuilder,
};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::utils;

/// Derived key from a password
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey {
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
}

/// Parameters for key derivation
pub struct KeyDerivationParams {
    /// Memory cost (in KB)
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Parallelism factor
    pub parallelism: u32,
    /// Output key length in bytes
    pub key_length: usize,
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        Self {
            // These are reasonable defaults for most applications
            memory_cost: 65536, // 64 MB
            time_cost: 3,
            parallelism: 4,
            key_length: 32, // 256 bits
        }
    }
}

/// Low-resource mode for constrained environments
pub fn low_resource_params() -> KeyDerivationParams {
    KeyDerivationParams {
        memory_cost: 19456, // 19 MB
        time_cost: 2,
        parallelism: 1,
        key_length: 32,
    }
}

/// High-security mode for sensitive keys
pub fn high_security_params() -> KeyDerivationParams {
    KeyDerivationParams {
        memory_cost: 262144, // 256 MB
        time_cost: 4,
        parallelism: 8,
        key_length: 32,
    }
}

/// Derives a key from a password
///
/// # Arguments
///
/// * `password` - The password to derive a key from
/// * `salt` - Optional salt to use (generates a new one if None)
/// * `params` - Optional parameters for key derivation (uses defaults if None)
///
/// # Returns
///
/// A DerivedKey containing the derived key and salt used
pub fn derive_key_from_password(
    password: &str,
    salt: Option<&[u8]>,
    params: Option<&KeyDerivationParams>,
) -> Result<DerivedKey, CryptoError> {
    let default_params = KeyDerivationParams::default();
    let params = params.unwrap_or(&default_params);
    
    // Create Argon2 params
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(params.memory_cost)
        .t_cost(params.time_cost)
        .p_cost(params.parallelism)
        .output_len(params.key_length);
    
    let argon2_params = builder.build().map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to build Argon2 parameters: {}", e))
    })?;
    
    // Create Argon2 instance with the specified parameters
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );
    
    // Generate salt if not provided
    let salt_string = match salt {
        Some(s) => SaltString::encode_b64(s).map_err(|e| {
            CryptoError::KeyManagementError(format!("Failed to encode salt: {}", e))
        })?,
        None => SaltString::generate(&mut OsRng),
    };
    
    // Hash the password with the salt to derive the key
    let derived = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| {
            CryptoError::KeyManagementError(format!("Failed to derive key: {}", e))
        })?;
    
    // Extract the hash as the derived key
    let hash = derived.hash.unwrap();
    let hash_bytes = hash.as_bytes();
    let key = hash_bytes[..params.key_length].to_vec();
    
    // Get the salt bytes
    let salt_bytes = salt_string.as_str().as_bytes().to_vec();
    
    Ok(DerivedKey {
        key,
        salt: salt_bytes,
    })
}

/// Verifies a password against a derived key
///
/// # Arguments
///
/// * `password` - The password to verify
/// * `derived_key` - The previously derived key to check against
/// * `params` - Optional parameters for key derivation (uses defaults if None)
///
/// # Returns
///
/// `Ok(true)` if the password matches, `Ok(false)` if not, or an error
pub fn verify_password(
    password: &str,
    derived_key: &DerivedKey,
    params: Option<&KeyDerivationParams>,
) -> Result<bool, CryptoError> {
    // Derive a key using the same salt
    let test_derived = derive_key_from_password(password, Some(&derived_key.salt), params)?;
    
    // Compare the keys in constant time
    let result = utils::constant_time_eq(&test_derived.key, &derived_key.key);
    
    Ok(result)
}

/// Generates a cryptographically secure random salt
///
/// # Arguments
///
/// * `length` - Length of the salt in bytes
///
/// # Returns
///
/// A vector containing the random salt
pub fn generate_salt(length: usize) -> Result<Vec<u8>, CryptoError> {
    utils::random_bytes(length)
}

/// Changes the password for a derived key
///
/// # Arguments
///
/// * `old_password` - The current password
/// * `new_password` - The new password to use
/// * `derived_key` - The current derived key
/// * `params` - Optional parameters for key derivation (uses defaults if None)
///
/// # Returns
///
/// A new DerivedKey if successful, or an error if the old password is incorrect
pub fn change_password(
    old_password: &str,
    new_password: &str,
    derived_key: &DerivedKey,
    params: Option<&KeyDerivationParams>,
) -> Result<DerivedKey, CryptoError> {
    // Verify the old password first
    if !verify_password(old_password, derived_key, params)? {
        return Err(CryptoError::KeyManagementError(
            "Invalid password".to_string(),
        ));
    }
    
    // Generate a new derived key with the new password
    derive_key_from_password(new_password, None, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_derive_key() {
        let password = "secure_password123";
        let derived = derive_key_from_password(password, None, None).unwrap();
        
        assert_eq!(derived.key.len(), 32); // Default key length
        assert!(!derived.salt.is_empty());
    }
    
    #[test]
    fn test_verify_password() {
        let password = "secure_password123";
        let derived = derive_key_from_password(password, None, None).unwrap();
        
        // Correct password
        let result = verify_password(password, &derived, None).unwrap();
        assert!(result);
        
        // Incorrect password
        let result = verify_password("wrong_password", &derived, None).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_with_custom_salt() {
        let password = "secure_password123";
        let salt = generate_salt(16).unwrap();
        
        let derived1 = derive_key_from_password(password, Some(&salt), None).unwrap();
        let derived2 = derive_key_from_password(password, Some(&salt), None).unwrap();
        
        // Same password + same salt should give same key
        assert_eq!(derived1.key, derived2.key);
    }
    
    #[test]
    fn test_with_custom_params() {
        let params = KeyDerivationParams {
            memory_cost: 16384,
            time_cost: 2,
            parallelism: 2,
            key_length: 16,
        };
        
        let password = "secure_password123";
        let derived = derive_key_from_password(password, None, Some(&params)).unwrap();
        
        // Key length should match params
        assert_eq!(derived.key.len(), 16);
    }
    
    #[test]
    fn test_change_password() {
        let old_password = "old_password123";
        let new_password = "new_secure_password";
        
        let derived = derive_key_from_password(old_password, None, None).unwrap();
        let new_derived = change_password(old_password, new_password, &derived, None).unwrap();
        
        // Verify old password no longer works
        let old_result = verify_password(old_password, &new_derived, None).unwrap();
        assert!(!old_result);
        
        // Verify new password works
        let new_result = verify_password(new_password, &new_derived, None).unwrap();
        assert!(new_result);
    }
    
    #[test]
    fn test_wrong_password_change() {
        let password = "secure_password123";
        let derived = derive_key_from_password(password, None, None).unwrap();
        
        // Try to change with wrong password
        let result = change_password("wrong_password", "new_password", &derived, None);
        assert!(result.is_err());
    }
}
