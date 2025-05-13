// Key rotation implementation
// This file contains code moved from src/key_management.rs for key rotation

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::dilithium::{DilithiumKeyPair, DilithiumVariant};
use crate::error::CryptoError;
use crate::key_management::storage;
use crate::kyber::{KyberKeyPair, KyberVariant};

/// Key rotation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// How often keys should be rotated, in days
    pub rotation_interval_days: u32,
    /// Whether to keep old keys after rotation
    pub keep_old_keys: bool,
    /// How many old keys to keep (if keep_old_keys is true)
    pub old_keys_to_keep: u8,
    /// Whether to automatically rotate keys that are due
    pub auto_rotate: bool,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            rotation_interval_days: 90, // 3 months
            keep_old_keys: true,
            old_keys_to_keep: 2,
            auto_rotate: false,
        }
    }
}

impl RotationPolicy {
    /// Create a new key rotation policy
    pub fn new(rotation_interval_days: u32) -> Self {
        Self {
            rotation_interval_days,
            ..Default::default()
        }
    }

    /// Get the rotation interval in days
    pub fn get_interval(&self) -> u32 {
        self.rotation_interval_days
    }
    
    /// Create a policy with high security (frequent rotation)
    pub fn high_security() -> Self {
        Self {
            rotation_interval_days: 30, // 1 month
            keep_old_keys: true,
            old_keys_to_keep: 3,
            auto_rotate: true,
        }
    }
    
    /// Create a policy with standard security (moderate rotation)
    pub fn standard_security() -> Self {
        Self::default()
    }
    
    /// Create a policy with minimal security (infrequent rotation)
    pub fn minimal_security() -> Self {
        Self {
            rotation_interval_days: 365, // 1 year
            keep_old_keys: true,
            old_keys_to_keep: 1,
            auto_rotate: false,
        }
    }
}

/// Metadata for key rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationMetadata {
    /// When the key was created
    pub created_at: DateTime<Utc>,
    /// When the key was last rotated (or None if never rotated)
    pub last_rotated: Option<DateTime<Utc>>,
    /// The policy applied to this key
    pub policy: RotationPolicy,
    /// IDs of previous versions of this key (most recent first)
    pub previous_key_ids: Vec<String>,
}

impl KeyRotationMetadata {
    /// Create new metadata with the current time
    pub fn new(policy: RotationPolicy) -> Self {
        Self {
            created_at: Utc::now(),
            last_rotated: None,
            policy,
            previous_key_ids: Vec::new(),
        }
    }
    
    /// Check if the key is due for rotation according to policy
    pub fn is_rotation_due(&self) -> bool {
        let reference_time = self.last_rotated.unwrap_or(self.created_at);
        let rotation_duration = Duration::days(self.policy.rotation_interval_days as i64);
        let now = Utc::now();
        
        now > reference_time + rotation_duration
    }
    
    /// Update the metadata after a rotation
    pub fn update_after_rotation(&mut self, old_key_id: String) {
        // Set last rotated to current time
        self.last_rotated = Some(Utc::now());
        
        // Add the old key ID to the list of previous keys
        self.previous_key_ids.insert(0, old_key_id);
        
        // Limit the number of previous keys according to policy
        if !self.policy.keep_old_keys {
            self.previous_key_ids.clear();
        } else if self.previous_key_ids.len() > self.policy.old_keys_to_keep as usize {
            self.previous_key_ids.truncate(self.policy.old_keys_to_keep as usize);
        }
    }
}

/// Path for storing rotation metadata
fn get_metadata_path(key_id: &str, key_type: &str) -> PathBuf {
    let mut dir = storage::get_key_storage_directory();
    dir.push(format!("{}.{}.metadata", key_id, key_type));
    dir
}

/// Save rotation metadata to disk
fn save_metadata(key_id: &str, key_type: &str, metadata: &KeyRotationMetadata) -> Result<(), CryptoError> {
    let path = get_metadata_path(key_id, key_type);
    
    let data = bincode::serialize(metadata)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to serialize metadata: {}", e)))?;
        
    let mut file = File::create(&path)
        .map_err(|e| CryptoError::KeyManagementError(format!("Failed to create metadata file: {}", e)))?;
        
    file.write_all(&data)
        .map_err(|e| CryptoError::KeyManagementError(format!("Failed to write metadata: {}", e)))?;
        
    Ok(())
}

/// Load rotation metadata from disk
fn load_metadata(key_id: &str, key_type: &str) -> Result<KeyRotationMetadata, CryptoError> {
    let path = get_metadata_path(key_id, key_type);
    
    if !path.exists() {
        // Create default metadata if it doesn't exist
        let metadata = KeyRotationMetadata::new(RotationPolicy::default());
        save_metadata(key_id, key_type, &metadata)?;
        return Ok(metadata);
    }
    
    let mut file = File::open(&path)
        .map_err(|e| CryptoError::KeyManagementError(format!("Failed to open metadata file: {}", e)))?;
        
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| CryptoError::KeyManagementError(format!("Failed to read metadata: {}", e)))?;
        
    let metadata = bincode::deserialize(&data)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize metadata: {}", e)))?;
        
    Ok(metadata)
}

/// Rotate a Kyber key pair
///
/// # Arguments
///
/// * `key_id` - ID of the key to rotate
/// * `password` - Password to decrypt the key
///
/// # Returns
///
/// The ID of the new key pair, or an error
pub fn rotate_kyber_keypair(
    key_id: &str,
    password: &str,
) -> Result<String, CryptoError> {
    // Load the existing key
    let old_keypair = storage::load_kyber_keypair(key_id, password)?;
    
    // Generate a new key with the same algorithm
    let new_keypair = KyberKeyPair::generate(old_keypair.algorithm)?;
    
    // Store the new key
    let new_key_id = storage::store_kyber_keypair(&new_keypair, None, password)?;
    
    // Load or create metadata for the new key
    let mut metadata = load_metadata(&new_key_id, "kyber")?;
    
    // Update metadata with rotation information
    metadata.update_after_rotation(key_id.to_string());
    
    // Save updated metadata
    save_metadata(&new_key_id, "kyber", &metadata)?;
    
    // Update the old key's last_rotated field to indicate it was rotated
    if let Ok(mut old_metadata) = load_metadata(key_id, "kyber") {
        old_metadata.last_rotated = Some(Utc::now());
        let _ = save_metadata(key_id, "kyber", &old_metadata);
    }
    
    Ok(new_key_id)
}

/// Rotate a Dilithium key pair
///
/// # Arguments
///
/// * `key_id` - ID of the key to rotate
/// * `password` - Password to decrypt the key
///
/// # Returns
///
/// The ID of the new key pair, or an error
pub fn rotate_dilithium_keypair(
    key_id: &str,
    password: &str,
) -> Result<String, CryptoError> {
    // Load the existing key
    let old_keypair = storage::load_dilithium_keypair(key_id, password)?;
    
    // Generate a new key with the same algorithm
    let new_keypair = DilithiumKeyPair::generate(old_keypair.algorithm)?;
    
    // Store the new key
    let new_key_id = storage::store_dilithium_keypair(&new_keypair, None, password)?;
    
    // Load or create metadata for the new key
    let mut metadata = load_metadata(&new_key_id, "dilithium")?;
    
    // Update metadata with rotation information
    metadata.update_after_rotation(key_id.to_string());
    
    // Save updated metadata
    save_metadata(&new_key_id, "dilithium", &metadata)?;
    
    // Update the old key's last_rotated field to indicate it was rotated
    if let Ok(mut old_metadata) = load_metadata(key_id, "dilithium") {
        old_metadata.last_rotated = Some(Utc::now());
        let _ = save_metadata(key_id, "dilithium", &old_metadata);
    }
    
    Ok(new_key_id)
}

/// Check if keys are due for rotation according to policy
///
/// # Returns
///
/// A vector of tuples with (key_id, key_type) for keys that need rotation
pub fn check_keys_for_rotation() -> Result<Vec<(String, String)>, CryptoError> {
    let keys = storage::list_keys()?;
    let mut keys_to_rotate = Vec::new();
    
    for (key_id, key_type) in keys {
        // Load metadata for the key
        match load_metadata(&key_id, &key_type) {
            Ok(metadata) => {
                // Check if rotation is due based on policy
                if metadata.is_rotation_due() {
                    keys_to_rotate.push((key_id, key_type));
                }
            },
            Err(_) => {
                // If metadata can't be loaded, create default metadata
                let default_metadata = KeyRotationMetadata::new(RotationPolicy::default());
                let _ = save_metadata(&key_id, &key_type, &default_metadata);
            }
        }
    }
    
    Ok(keys_to_rotate)
}

/// Automatically rotate all keys that are due according to policy
///
/// # Arguments
///
/// * `password_provider` - A function that provides the password for a given key ID
///
/// # Returns
///
/// A vector of tuples containing (old_key_id, new_key_id) for rotated keys
pub fn auto_rotate_keys<F>(password_provider: F) -> Result<Vec<(String, String)>, CryptoError>
where
    F: Fn(&str) -> Result<String, CryptoError>,
{
    let keys_to_rotate = check_keys_for_rotation()?;
    let mut rotated_keys = Vec::new();
    
    for (key_id, key_type) in keys_to_rotate {
        // Get the password for this key
        let password = password_provider(&key_id)?;
        
        // Determine the key type and rotate
        let new_key_id = match key_type.as_str() {
            "kyber" => rotate_kyber_keypair(&key_id, &password)?,
            "dilithium" => rotate_dilithium_keypair(&key_id, &password)?,
            _ => continue,
        };
        
        rotated_keys.push((key_id, new_key_id));
    }
    
    Ok(rotated_keys)
}

/// Calculate key age and provide recommendations for rotation
///
/// # Arguments
///
/// * `key_id` - ID of the key to check
/// * `key_type` - Type of the key ("kyber" or "dilithium")
///
/// # Returns
///
/// A KeyAgeSummary containing age information and recommendations
pub fn get_key_age(key_id: &str, key_type: &str) -> Result<KeyAgeSummary, CryptoError> {
    // Load metadata for the key
    let metadata = load_metadata(key_id, key_type)?;
    
    // Calculate days since creation
    let now = Utc::now();
    let days_since_creation = (now - metadata.created_at).num_days() as u32;
    
    // Calculate days since last rotation (if any)
    let days_since_rotation = metadata.last_rotated.map(|last_rotated| {
        (now - last_rotated).num_days() as u32
    });
    
    // Calculate days until next rotation
    let reference_time = metadata.last_rotated.unwrap_or(metadata.created_at);
    let next_rotation = reference_time + Duration::days(metadata.policy.rotation_interval_days as i64);
    
    let days_until_next_rotation = if now > next_rotation {
        0
    } else {
        (next_rotation - now).num_days() as u32
    };
    
    // Determine if rotation is recommended
    let rotation_recommended = days_until_next_rotation == 0;
    
    Ok(KeyAgeSummary {
        days_since_creation,
        days_since_rotation,
        days_until_next_rotation,
        rotation_recommended,
    })
}

/// Summary of key age information
#[derive(Debug, Clone)]
pub struct KeyAgeSummary {
    /// Days since the key was created
    pub days_since_creation: u32,
    /// Days since the key was last rotated (None if never rotated)
    pub days_since_rotation: Option<u32>,
    /// Days until the next rotation is due
    pub days_until_next_rotation: u32,
    /// Whether rotation is recommended now
    pub rotation_recommended: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;
    
    #[test]
    fn test_is_rotation_due() {
        let policy = RotationPolicy::new(90);
        let mut metadata = KeyRotationMetadata::new(policy);
        
        // Set created_at to 100 days ago
        metadata.created_at = Utc::now() - Duration::days(100);
        
        // No rotation has happened, so it should be due
        assert!(metadata.is_rotation_due());
        
        // Set last_rotated to 30 days ago
        metadata.last_rotated = Some(Utc::now() - Duration::days(30));
        
        // Last rotation was recent, so it should not be due
        assert!(!metadata.is_rotation_due());
        
        // Set last_rotated to 100 days ago
        metadata.last_rotated = Some(Utc::now() - Duration::days(100));
        
        // Last rotation was too long ago, so it should be due
        assert!(metadata.is_rotation_due());
    }
    
    #[test]
    fn test_update_after_rotation() {
        let policy = RotationPolicy {
            rotation_interval_days: 90,
            keep_old_keys: true,
            old_keys_to_keep: 2,
            auto_rotate: false,
        };
        
        let mut metadata = KeyRotationMetadata::new(policy.clone());
        
        // Initial state
        assert!(metadata.previous_key_ids.is_empty());
        assert_eq!(metadata.last_rotated, None);
        
        // First rotation
        metadata.update_after_rotation("key1".to_string());
        assert_eq!(metadata.previous_key_ids, vec!["key1"]);
        assert!(metadata.last_rotated.is_some());
        
        // Second rotation
        let first_rotation_time = metadata.last_rotated.unwrap();
        metadata.update_after_rotation("key2".to_string());
        assert_eq!(metadata.previous_key_ids, vec!["key2", "key1"]);
        assert!(metadata.last_rotated.unwrap() > first_rotation_time);
        
        // Third rotation (should limit to 2 previous keys)
        metadata.update_after_rotation("key3".to_string());
        assert_eq!(metadata.previous_key_ids, vec!["key3", "key2"]);
        
        // Test with keep_old_keys = false
        let policy_no_keep = RotationPolicy {
            keep_old_keys: false,
            ..policy.clone()
        };
        
        let mut metadata_no_keep = KeyRotationMetadata::new(policy_no_keep);
        metadata_no_keep.previous_key_ids = vec!["old1".to_string(), "old2".to_string()];
        
        metadata_no_keep.update_after_rotation("key4".to_string());
        assert!(metadata_no_keep.previous_key_ids.is_empty());
    }
    
    #[test]
    fn test_metadata_save_load() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();
        
        // Override storage directory for testing
        let original_get_dir = storage::get_key_storage_directory;
        storage::get_key_storage_directory = || temp_path.to_path_buf();
        
        let policy = RotationPolicy::default();
        let original_metadata = KeyRotationMetadata::new(policy);
        
        // Test saving metadata
        save_metadata("test-key", "kyber", &original_metadata).unwrap();
        
        // Test loading metadata
        let loaded_metadata = load_metadata("test-key", "kyber").unwrap();
        
        // Verify metadata is the same
        assert_eq!(loaded_metadata.created_at, original_metadata.created_at);
        assert_eq!(loaded_metadata.last_rotated, original_metadata.last_rotated);
        assert_eq!(loaded_metadata.policy.rotation_interval_days, original_metadata.policy.rotation_interval_days);
        assert_eq!(loaded_metadata.policy.keep_old_keys, original_metadata.policy.keep_old_keys);
        assert_eq!(loaded_metadata.previous_key_ids, original_metadata.previous_key_ids);
        
        // Restore original function
        storage::get_key_storage_directory = original_get_dir;
    }
}
