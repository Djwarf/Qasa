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
///
/// This structure contains the output of a password-based key derivation function
/// along with the salt that was used to derive it. Both pieces are needed to 
/// verify passwords and to derive the same key again.
///
/// # Security Properties
///
/// 1. Implements secure memory handling through Zeroize and ZeroizeOnDrop
/// 2. Automatically zeroes memory when dropped to prevent key material leakage
/// 3. Can be safely cloned with independent zeroization of each instance
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    /// The derived key
    pub key: Vec<u8>,
    /// The salt used to derive the key
    pub salt: Vec<u8>,
}

/// Parameters for key derivation
///
/// This structure defines the computational parameters for the Argon2id
/// password hashing algorithm. These parameters control the security/performance
/// tradeoff of the key derivation process.
///
/// # Security Considerations
///
/// 1. Higher memory and time costs provide better security against brute force attacks
/// 2. Parameters should be tuned based on the security requirements and hardware constraints
/// 3. For sensitive keys, use the high_security_params() preset
/// 4. For resource-constrained environments, use low_resource_params() preset
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

/// Get key derivation parameters optimized for constrained environments
///
/// This function returns parameters suitable for resource-constrained environments
/// such as embedded devices, mobile phones, or systems with limited memory.
/// These parameters provide a reasonable security margin while minimizing
/// resource usage.
///
/// # Returns
///
/// KeyDerivationParams with reduced memory and CPU requirements
///
/// # Security Considerations
///
/// While these parameters provide acceptable security for most uses, they
/// offer less protection against brute force attacks compared to the default
/// or high-security parameters. Use only when resource constraints are significant.
pub fn low_resource_params() -> KeyDerivationParams {
    KeyDerivationParams {
        memory_cost: 19456, // 19 MB
        time_cost: 2,
        parallelism: 1,
        key_length: 32,
    }
}

/// Get key derivation parameters optimized for high-security applications
///
/// This function returns parameters suitable for high-security environments
/// where protection of sensitive keys is paramount and computational resources
/// are abundant.
///
/// # Returns
///
/// KeyDerivationParams with increased memory and CPU requirements for maximum security
///
/// # Security Considerations
///
/// These parameters are designed to make brute-force attacks computationally
/// expensive, but will require more system resources during key derivation.
/// Suitable for deriving master keys or keys protecting highly sensitive data.
pub fn high_security_params() -> KeyDerivationParams {
    KeyDerivationParams {
        memory_cost: 262144, // 256 MB
        time_cost: 4,
        parallelism: 8,
        key_length: 32,
    }
}

/// Internal helper function to derive a key using common parameters
///
/// This is an internal function that implements the core key derivation logic
/// using Argon2id. It is used by the public key derivation functions and
/// should not be called directly by most users.
///
/// # Arguments
///
/// * `password` - The password bytes to derive a key from
/// * `salt` - The salt bytes to use in derivation
/// * `params` - The parameters controlling the derivation process
///
/// # Returns
///
/// The derived key bytes or an error
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

/// Derives a cryptographic key from a password using Argon2id
///
/// This function performs secure password-based key derivation using the
/// Argon2id algorithm, which is designed to be resistant to both side-channel
/// attacks and specialized hardware attacks. The resulting key can be used
/// for encryption, authentication, or other cryptographic purposes.
///
/// # Arguments
///
/// * `password` - The user password to derive a key from
/// * `salt` - Optional salt to use (generates a new random salt if None)
/// * `params` - Optional parameters for key derivation (uses defaults if None)
///
/// # Returns
///
/// A DerivedKey containing the derived key and salt used, or an error
///
/// # Security Considerations
///
/// 1. The password is handled securely using SecureBytes to prevent memory leaks
/// 2. Uses Argon2id, a memory-hard function resistant to GPU/ASIC acceleration
/// 3. Generates a cryptographically secure random salt if none is provided
/// 4. The default parameters provide a good balance of security and performance
///
/// # Example
///
/// ```
/// use qasa::key_management::derive_key_from_password;
///
/// // Derive a key with default parameters and a new random salt
/// let derived_key = derive_key_from_password("secure_user_password", None, None).unwrap();
///
/// // The derived key can now be used for encryption or other purposes
/// // The salt should be stored alongside the key for password verification
/// ```
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

/// Verifies a password against a previously derived key
///
/// This function checks if a provided password matches the one that was used
/// to create a derived key. It does this by performing the same key derivation
/// process with the provided password and stored salt, then comparing the result
/// with the stored key using a constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `password` - The password to verify
/// * `derived_key` - The previously derived key to check against
/// * `params` - Optional parameters for key derivation (uses defaults if None)
///
/// # Returns
///
/// * `Ok(true)` if the password matches
/// * `Ok(false)` if the password does not match
/// * `Err(CryptoError)` if an error occurs during verification
///
/// # Security Considerations
///
/// 1. Uses constant-time comparison to prevent timing attacks
/// 2. Handles the password securely using SecureBytes
/// 3. Uses the same parameters and salt as the original key derivation
///
/// # Example
///
/// ```
/// use qasa::key_management::{derive_key_from_password, verify_password};
///
/// // First derive a key from a password
/// let original_key = derive_key_from_password("user_password", None, None).unwrap();
///
/// // Later, verify a password against the stored key
/// let is_valid = verify_password("user_password", &original_key, None).unwrap();
/// assert!(is_valid); // Password matches
///
/// let is_valid = verify_password("wrong_password", &original_key, None).unwrap();
/// assert!(!is_valid); // Password doesn't match
/// ```
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

/// Generates a cryptographically secure random salt for key derivation
///
/// Salts are critical for password-based key derivation to prevent
/// precomputation attacks like rainbow tables. This function generates
/// a secure random salt of the specified length.
///
/// # Arguments
///
/// * `length` - Length of the salt in bytes (recommended: at least 16 bytes)
///
/// # Returns
///
/// A vector containing the random salt, or an error
///
/// # Security Considerations
///
/// 1. Uses a cryptographically secure random number generator
/// 2. Salt should be stored alongside the derived key
/// 3. Each user should have a unique salt
/// 4. Each key derivation should use a fresh salt when possible
pub fn generate_salt(length: usize) -> Result<Vec<u8>, CryptoError> {
    utils::random_bytes(length)
}

/// Changes the password for an existing derived key
///
/// This function allows securely changing the password for an existing key
/// by first verifying the old password, then deriving a new key with the
/// new password and a fresh salt.
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
///
/// # Security Considerations
///
/// 1. Verifies the old password before allowing the change
/// 2. Generates a new random salt for the new key
/// 3. The new key is derived with the same security parameters as the old one
/// 4. Passwords are handled securely in memory
///
/// # Example
///
/// ```
/// use qasa::key_management::{derive_key_from_password, change_password};
///
/// // First derive a key from the original password
/// let original_key = derive_key_from_password("old_password", None, None).unwrap();
///
/// // Change the password
/// let new_key = change_password(
///     "old_password",
///     "new_stronger_password",
///     &original_key,
///     None
/// ).unwrap();
///
/// // The new_key now contains the same cryptographic material but protected by
/// // the new password and a fresh salt
/// ```
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
