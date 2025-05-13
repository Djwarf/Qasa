// Password handling implementation
// This file contains code moved from src/key_management.rs for password handling

use argon2::{
    password_hash::SaltString,
    Argon2, ParamsBuilder,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::utils;
use crate::secure_memory::SecureBytes;

/// Derived key data, including the key itself and the salt used to generate it
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    /// The derived key
    pub key: Vec<u8>,
    /// The salt used to derive the key
    pub salt: Vec<u8>,
}

/// Parameters for key derivation
#[derive(Debug, Clone)]
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

/// Helper function to derive a key using common parameters
fn derive_key_internal(
    password: &[u8],
    salt: &[u8],
    params: &KeyDerivationParams,
) -> Result<Vec<u8>, CryptoError> {
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
    
    // Convert the salt to a SaltString
    let salt_string = SaltString::encode_b64(salt).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to encode salt: {}", e))
    })?;
    
    // Create a buffer for the output key
    let mut key_buffer = vec![0u8; params.key_length];
    
    // Derive the key using Argon2
    argon2.hash_password_into(
        password,
        salt_string.as_str().as_bytes(),
        &mut key_buffer
    ).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to derive key: {}", e))
    })?;
    
    Ok(key_buffer)
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
    // Create secure password handling
    let secure_password = SecureBytes::new(password.as_bytes());
    
    let default_params = KeyDerivationParams::default();
    let params = params.unwrap_or(&default_params);
    
    // Generate or use provided salt
    let salt_bytes = match salt {
        Some(s) => s.to_vec(),
        None => {
            // Generate fresh random salt
            utils::random_bytes(16)?
        },
    };
    
    // Derive the key
    let key_buffer = derive_key_internal(
        secure_password.as_bytes(),
        &salt_bytes,
        params
    )?;
    
    // Return the derived key and salt
    Ok(DerivedKey {
        key: key_buffer,
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
    // Create secure password handling
    let secure_password = SecureBytes::new(password.as_bytes());
    
    // Get parameters
    let default_params = KeyDerivationParams::default();
    let params = params.unwrap_or(&default_params);
    
    // Derive key with same salt
    let key = derive_key_internal(
        secure_password.as_bytes(),
        &derived_key.salt,
        params
    )?;
    
    // Compare the keys in constant time
    let result = utils::constant_time_eq(&key, &derived_key.key);
    
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
        return Err(CryptoError::InvalidPasswordError("Invalid password".to_string()));
    }
    
    // Generate a new derived key with the new password
    derive_key_from_password(new_password, None, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_memory::with_secure_scope;
    
    #[test]
    fn test_derive_key() {
        let password = "secure_password123";
        let derived = derive_key_from_password(password, None, None).unwrap();
        
        assert_eq!(derived.key.len(), 32, "Derived key should be 32 bytes long");
        assert!(!derived.salt.is_empty(), "Salt should not be empty");
    }
    
    #[test]
    fn test_verify_password() {
        let password = "secure_password123";
        let derived = derive_key_from_password(password, None, None).unwrap();
        
        // Correct password
        let result = verify_password(password, &derived, None).unwrap();
        assert!(result, "Password verification should succeed with correct password");
        
        // Incorrect password
        let result = verify_password("wrong_password", &derived, None).unwrap();
        assert!(!result, "Password verification should fail with incorrect password");
    }
    
    #[test]
    fn test_with_custom_salt() {
        let password = "secure_password123";
        let salt = generate_salt(16).unwrap();
        
        let derived1 = derive_key_from_password(password, Some(&salt), None).unwrap();
        let derived2 = derive_key_from_password(password, Some(&salt), None).unwrap();
        
        // Same password + same salt should give same key
        assert_eq!(derived1.key, derived2.key, "Same password+salt should produce same key");
        
        // The salt should be preserved exactly
        assert_eq!(derived1.salt, salt, "Salt should be preserved exactly");
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
        assert_eq!(derived.key.len(), 16, "Key length should match specified params");
    }
    
    #[test]
    fn test_change_password() {
        let old_password = "old_password123";
        let new_password = "new_secure_password";
        
        // First derive a key with the old password
        let derived = derive_key_from_password(old_password, None, None).unwrap();
        
        // Change the password
        let new_derived = change_password(old_password, new_password, &derived, None).unwrap();
        
        // Verify old password no longer works with new derived key
        let old_result = verify_password(old_password, &new_derived, None).unwrap();
        assert!(!old_result, "Old password should not work with new derived key");
        
        // Verify new password works with new derived key
        let new_result = verify_password(new_password, &new_derived, None).unwrap();
        assert!(new_result, "New password should work with new derived key");
    }
    
    #[test]
    fn test_wrong_password_change() {
        let password = "secure_password123";
        let derived = derive_key_from_password(password, None, None).unwrap();
        
        // Try to change with wrong password
        let result = change_password("wrong_password", "new_password", &derived, None);
        assert!(result.is_err(), "Password change should fail with incorrect old password");
        
        if let Err(CryptoError::InvalidPasswordError(_)) = result {
            // Expected error type
        } else {
            panic!("Unexpected error type");
        }
    }
    
    #[test]
    fn test_secure_memory_handling() {
        let password = "super_secure_password";
        
        // Use secure memory handling for the password
        let secure_password = SecureBytes::new(password.as_bytes());
        let password_str = std::str::from_utf8(secure_password.as_bytes()).unwrap();
        
        // Derive a key using the secure password
        let derived = derive_key_from_password(password_str, None, None).unwrap();
        
        // Verify the password still works
        let verification = verify_password(password, &derived, None).unwrap();
        assert!(verification, "Password verification should work after secure handling");
        
        // Test with scope-based zeroing
        let verification_scoped = with_secure_scope(&mut password.to_string(), |pwd| {
            verify_password(pwd, &derived, None)
        }).unwrap();
        
        assert!(verification_scoped, "Password verification should work with secure scope");
    }
}
