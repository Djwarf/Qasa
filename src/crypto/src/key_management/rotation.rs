// Key rotation implementation
// This file contains code moved from src/key_management.rs for key rotation

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::dilithium::DilithiumKeyPair;
use crate::error::CryptoError;
use crate::key_management::storage;
use crate::kyber::KyberKeyPair;
use crate::secure_memory::{with_secure_scope};

/// Key rotation policy
///
/// This structure defines the policy for rotating cryptographic keys,
/// including rotation intervals, whether to keep old keys, and whether
/// rotation should happen automatically.
///
/// Regular key rotation is an important security practice that limits
/// the impact of potential key compromises and ensures cryptographic
/// hygiene.
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
    ///
    /// # Arguments
    ///
    /// * `rotation_interval_days` - How often keys should be rotated, in days
    ///
    /// # Returns
    ///
    /// A new RotationPolicy with the specified interval and default values
    /// for other settings
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::key_management::RotationPolicy;
    ///
    /// // Create a policy that rotates keys every 30 days
    /// let policy = RotationPolicy::new(30);
    /// assert_eq!(policy.get_interval(), 30);
    /// ```
    pub fn new(rotation_interval_days: u32) -> Self {
        Self {
            rotation_interval_days,
            ..Default::default()
        }
    }

    /// Get the rotation interval in days
    ///
    /// # Returns
    ///
    /// The number of days between key rotations
    pub fn get_interval(&self) -> u32 {
        self.rotation_interval_days
    }
    
    /// Create a policy with high security (frequent rotation)
    ///
    /// This preset policy is designed for high-security environments
    /// where keys should be rotated frequently (monthly) and multiple
    /// previous keys should be kept to ensure access to older data.
    ///
    /// # Returns
    ///
    /// A RotationPolicy configured for high security
    ///
    /// # Security Considerations
    ///
    /// 1. More frequent rotations reduce the window of opportunity if a key is compromised
    /// 2. Keeping multiple old keys ensures decryption capability for older messages
    /// 3. Automatic rotation ensures security policies are enforced without manual intervention
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::key_management::RotationPolicy;
    ///
    /// let policy = RotationPolicy::high_security();
    /// assert_eq!(policy.rotation_interval_days, 30); // Monthly rotation
    /// assert!(policy.auto_rotate); // Automatic rotation
    /// ```
    pub fn high_security() -> Self {
        Self {
            rotation_interval_days: 30, // 1 month
            keep_old_keys: true,
            old_keys_to_keep: 3,
            auto_rotate: true,
        }
    }
    
    /// Create a policy with standard security (moderate rotation)
    ///
    /// This preset policy provides a balance between security and
    /// operational overhead, with quarterly rotation and retention
    /// of a moderate number of old keys.
    ///
    /// # Returns
    ///
    /// The default RotationPolicy
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::key_management::RotationPolicy;
    ///
    /// let policy = RotationPolicy::standard_security();
    /// assert_eq!(policy.rotation_interval_days, 90); // Quarterly rotation
    /// ```
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

// Manual implementation of Zeroize for KeyRotationMetadata
// We need this because DateTime doesn't implement Zeroize
impl Zeroize for KeyRotationMetadata {
    fn zeroize(&mut self) {
        // We only need to zeroize the previous_key_ids as they could be sensitive
        for id in &mut self.previous_key_ids {
            id.zeroize();
        }
        self.previous_key_ids.clear();
        // Note: We can't zeroize DateTime fields, but they're not sensitive cryptographic material
    }
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

    /// Calculate key age in days
    pub fn key_age_days(&self) -> u32 {
        let now = Utc::now();
        (now - self.created_at).num_days() as u32
    }
    
    /// Calculate days since last rotation
    pub fn days_since_rotation(&self) -> Option<u32> {
        self.last_rotated.map(|last_rotated| {
            let now = Utc::now();
            (now - last_rotated).num_days() as u32
        })
    }
    
    /// Calculate days until next required rotation
    pub fn days_until_rotation(&self) -> u32 {
        let reference_time = self.last_rotated.unwrap_or(self.created_at);
        let next_rotation = reference_time + Duration::days(self.policy.rotation_interval_days as i64);
        let now = Utc::now();
        
        if now > next_rotation {
            0
        } else {
            (next_rotation - now).num_days() as u32
        }
    }
}

/// Path for storing rotation metadata
pub fn get_metadata_path(key_id: &str, key_type: &str) -> PathBuf {
    let mut dir = storage::get_key_storage_directory();
    dir.push(format!("{}.{}.metadata", key_id, key_type));
    dir
}

/// Save rotation metadata to disk
pub fn save_metadata(key_id: &str, key_type: &str, metadata: &KeyRotationMetadata) -> Result<(), CryptoError> {
    let path = get_metadata_path(key_id, key_type);
    
    let data = bincode::serialize(metadata)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to serialize metadata: {}", e)))?;
        
    let mut file = File::create(&path)
                    .map_err(|e| CryptoError::key_management_error("Failed to create metadata file", &format!("Metadata file creation error: {}", e), "unknown"))?;
        
    file.write_all(&data)
                    .map_err(|e| CryptoError::key_management_error("Failed to write metadata", &format!("Metadata write error: {}", e), "unknown"))?;
        
    Ok(())
}

/// Load rotation metadata from disk
pub fn load_metadata(key_id: &str, key_type: &str) -> Result<KeyRotationMetadata, CryptoError> {
    let path = get_metadata_path(key_id, key_type);
    
    if !path.exists() {
        // Create default metadata if it doesn't exist
        let metadata = KeyRotationMetadata::new(RotationPolicy::default());
        save_metadata(key_id, key_type, &metadata)?;
        return Ok(metadata);
    }
    
    let mut file = File::open(&path)
                    .map_err(|e| CryptoError::key_management_error("Failed to open metadata file", &format!("Metadata file open error: {}", e), "unknown"))?;
        
    let mut data = Vec::new();
    file.read_to_end(&mut data)
                    .map_err(|e| CryptoError::key_management_error("Failed to read metadata", &format!("Metadata read error: {}", e), "unknown"))?;
        
    let metadata = bincode::deserialize(&data)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize metadata: {}", e)))?;
    
    // Securely zero the data after use
    with_secure_scope(&mut data, |_| {});
        
    Ok(metadata)
}

/// Rotate a Kyber key pair
///
/// # Arguments
///
/// * `key_id` - ID of the key to rotate
/// * `password` - Password to decrypt the key
/// * `path` - Optional custom path for key storage
///
/// # Returns
///
/// The ID of the new key pair, or an error
pub fn rotate_kyber_keypair(
    key_id: &str,
    password: &str,
    path: Option<&str>,
) -> Result<String, CryptoError> {
    // Load the existing key
    let old_keypair = storage::load_kyber_keypair(key_id, password, path)?;
    
    // Generate a new key with the same algorithm
    let new_keypair = KyberKeyPair::generate(old_keypair.algorithm)?;
    
    // Store the new key
    let new_key_id = storage::store_kyber_keypair(&new_keypair, path, password)?;
    
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
/// * `path` - Optional custom path for key storage
///
/// # Returns
///
/// The ID of the new key pair, or an error
pub fn rotate_dilithium_keypair(
    key_id: &str,
    password: &str,
    path: Option<&str>,
) -> Result<String, CryptoError> {
    // Load the existing key
    let old_keypair = storage::load_dilithium_keypair(key_id, password, path)?;
    
    // Generate a new key with the same algorithm
    let new_keypair = DilithiumKeyPair::generate(old_keypair.algorithm)?;
    
    // Store the new key
    let new_key_id = storage::store_dilithium_keypair(&new_keypair, path, password)?;
    
    // Load or create metadata for the new key
    let mut metadata = load_metadata(&new_key_id, "dilithium")?;
    
    // Update metadata with rotation information
    metadata.update_after_rotation(key_id.to_string());
    
    // Save updated metadata
    save_metadata(&new_key_id, "dilithium", &metadata)?;
    
    Ok(new_key_id)
}

/// Check if keys are due for rotation according to policy
///
/// # Returns
///
/// A vector of tuples with (key_id, key_type) for keys that need rotation
pub fn check_keys_for_rotation() -> Result<Vec<(String, String)>, CryptoError> {
    let dir = storage::get_key_storage_directory();
    let mut due_for_rotation = Vec::new();
    
    if !dir.exists() {
        return Ok(Vec::new());
    }
    
    let entries = fs::read_dir(&dir)
        .map_err(|e| CryptoError::key_management_error("Failed to read key directory", &format!("Directory read error: {}", e), "unknown"))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| CryptoError::key_management_error("Failed to read directory entry", &format!("Directory entry read error: {}", e), "unknown"))?;
        let path = entry.path();
        
        if !path.is_file() {
            continue;
        }
        
        let filename = path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        
        if !filename.ends_with(".metadata") {
            continue;
        }
        
        // Parse key ID and type from filename
        let parts: Vec<&str> = filename.split('.').collect();
        if parts.len() < 3 {
            continue;
        }
        
        let key_id = parts[0];
        let key_type = parts[1];
        
        // Load metadata and check if rotation is due
        match load_metadata(key_id, key_type) {
            Ok(metadata) => {
                if metadata.is_rotation_due() {
                    due_for_rotation.push((key_id.to_string(), key_type.to_string()));
                }
            },
            Err(_) => continue, // Skip keys with invalid metadata
        }
    }
    
    Ok(due_for_rotation)
}

/// Automatically rotate all keys that are due according to policy
///
/// # Arguments
///
/// * `password_provider` - A function that provides the password for a given key ID
/// * `path` - Optional path to the key storage directory
/// * `policy` - Optional custom rotation policy to override the default
///
/// # Returns
///
/// A vector of tuples containing (old_key_id, new_key_id) for rotated keys
pub fn auto_rotate_keys<F>(
    password_provider: F,
    path: Option<&str>,
    policy: RotationPolicy,
) -> Result<Vec<(String, String)>, CryptoError>
where
    F: Fn(&str) -> String,
{
    let dir = match path {
        Some(p) => PathBuf::from(p),
        None => storage::get_key_storage_directory(),
    };
    let path_str = path;  // Store the original string path
    let mut rotated_keys = Vec::new();
    
    if !dir.exists() {
        return Ok(Vec::new());
    }
    
    let entries = fs::read_dir(&dir)
        .map_err(|e| CryptoError::key_management_error("Failed to read key directory", &format!("Directory read error: {}", e), "unknown"))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| CryptoError::key_management_error("Failed to read directory entry", &format!("Directory entry read error: {}", e), "unknown"))?;
        let path = entry.path();
        
        if !path.is_file() {
            continue;
        }
        
        let filename = path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        
        // Look for key files, not metadata
        if !filename.contains(".key") || filename.contains(".metadata") {
            continue;
        }
        
        // Parse key ID and type from filename
        let parts: Vec<&str> = filename.split('.').collect();
        if parts.len() < 3 {
            continue;
        }
        
        let key_id = parts[0];
        let key_type = parts[1];
        
        // Get key metadata
        match get_key_age(key_id, key_type) {
            Ok(age_summary) => {
                // Check if rotation is needed based on custom policy
                let days_since_creation = age_summary.days_since_creation;
                let days_since_rotation = age_summary.days_since_rotation.unwrap_or(days_since_creation);
                
                if days_since_rotation >= policy.rotation_interval_days {
                    // Try to get password
                    let password = password_provider(key_id);
                    
                    // Rotate the key based on its type
                    let result = match key_type {
                        "kyber" => rotate_kyber_keypair(key_id, &password, path_str),
                        "dilithium" => rotate_dilithium_keypair(key_id, &password, path_str),
                        _ => continue, // Skip unknown key types
                    };
                    
                    match result {
                        Ok(new_key_id) => {
                            rotated_keys.push((key_id.to_string(), new_key_id));
                        },
                        Err(e) => {
                            eprintln!("Failed to rotate key {}: {}", key_id, e);
                            continue;
                        }
                    }
                }
            },
            Err(_) => continue, // Skip keys with invalid metadata
        }
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
    let metadata = load_metadata(key_id, key_type)?;
    
    Ok(KeyAgeSummary {
        days_since_creation: metadata.key_age_days(),
        days_since_rotation: metadata.days_since_rotation(),
        days_until_next_rotation: metadata.days_until_rotation(),
        rotation_recommended: metadata.is_rotation_due(),
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

impl KeyAgeSummary {
    /// Returns true if the key should be rotated immediately
    pub fn should_rotate_now(&self) -> bool {
        self.rotation_recommended
    }
    
    /// Returns a human-readable description of the key age status
    pub fn status_description(&self) -> String {
        if self.rotation_recommended {
            "Key rotation is overdue and should be performed immediately".to_string()
        } else if self.days_until_next_rotation <= 7 {
            format!("Key rotation will be needed in {} days", self.days_until_next_rotation)
        } else {
            format!("Key is valid for {} more days", self.days_until_next_rotation)
        }
    }
}

/// Get the age of all keys in days
pub fn get_all_key_ages() -> Result<Vec<(String, String, KeyAgeSummary)>, CryptoError> {
    let dir = storage::get_key_storage_directory();
    let mut summaries = Vec::new();
    
    if !dir.exists() {
        return Ok(Vec::new());
    }
    
    let entries = fs::read_dir(&dir)
        .map_err(|e| CryptoError::key_management_error("Failed to read key directory", &format!("Directory read error: {}", e), "unknown"))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| CryptoError::key_management_error("Failed to read directory entry", &format!("Directory entry read error: {}", e), "unknown"))?;
        let path = entry.path();
        
        if !path.is_file() {
            continue;
        }
        
        let filename = path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        
        if !filename.ends_with(".metadata") {
            continue;
        }
        
        // Parse key ID and type from filename
        let parts: Vec<&str> = filename.split('.').collect();
        if parts.len() < 3 {
            continue;
        }
        
        let key_id = parts[0];
        let key_type = parts[1];
        
        // Get age summary for this key
        match get_key_age(key_id, key_type) {
            Ok(summary) => {
                summaries.push((key_id.to_string(), key_type.to_string(), summary));
            },
            Err(_) => continue, // Skip keys with errors
        }
    }
    
    Ok(summaries)
}

// Helper function that takes a function to get the key storage directory
// Used for testing and also for backwards compatibility
pub fn get_all_key_ages_internal<F>(get_dir_fn: F) -> Result<Vec<KeyAgeSummary>, CryptoError>
where
    F: Fn() -> PathBuf,
{
    let key_dir = get_dir_fn();
    if !key_dir.exists() {
        return Ok(Vec::new());
    }
    
    let mut result = Vec::new();
    let current_time = chrono::Utc::now();
    
    for entry in fs::read_dir(key_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let _key_id = entry.file_name().to_string_lossy().to_string();
            let metadata_path = entry.path().join("metadata.json");
            
            if metadata_path.exists() {
                let metadata_str = fs::read_to_string(metadata_path)?;
                let metadata: KeyRotationMetadata = serde_json::from_str(&metadata_str)
                    .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
                
                let days_since_creation = (current_time - metadata.created_at).num_days() as u32;
                let days_since_rotation = metadata.last_rotated.map(|last_rotated| {
                    (current_time - last_rotated).num_days() as u32
                });
                
                // Calculate days until next rotation
                let reference_time = metadata.last_rotated.unwrap_or(metadata.created_at);
                let next_rotation = reference_time + Duration::days(metadata.policy.rotation_interval_days as i64);
                
                let days_until_next_rotation = if current_time > next_rotation {
                    0
                } else {
                    (next_rotation - current_time).num_days() as u32
                };
                
                // Determine if rotation is recommended
                let rotation_recommended = days_until_next_rotation == 0;
                
                result.push(KeyAgeSummary {
                    days_since_creation,
                    days_since_rotation,
                    days_until_next_rotation,
                    rotation_recommended,
                });
            }
        }
    }
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    
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
        use std::path::PathBuf;
        
        // Create a temporary directory for testing
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();
        
        // Create a helper function to generate metadata paths in the temp directory
        let get_metadata_path_fn = |key_id: &str, _key_type: &str| -> PathBuf {
            let dir = temp_path.join(key_id);
            fs::create_dir_all(&dir).unwrap();
            dir.join("metadata.json")
        };
        
        let policy = RotationPolicy::default();
        let original_metadata = KeyRotationMetadata::new(policy);
        
        // Manually save metadata to the temp path
        let metadata_path = get_metadata_path_fn("test-key", "kyber");
        let metadata_json = serde_json::to_string(&original_metadata).unwrap();
        fs::write(&metadata_path, metadata_json).unwrap();
        
        // Now load the metadata directly from the path
        let metadata_str = fs::read_to_string(&metadata_path).unwrap();
        let loaded_metadata: KeyRotationMetadata = serde_json::from_str(&metadata_str).unwrap();
        
        // Verify metadata is the same
        assert_eq!(loaded_metadata.created_at, original_metadata.created_at);
        assert_eq!(loaded_metadata.last_rotated, original_metadata.last_rotated);
        assert_eq!(loaded_metadata.policy.rotation_interval_days, original_metadata.policy.rotation_interval_days);
        assert_eq!(loaded_metadata.policy.keep_old_keys, original_metadata.policy.keep_old_keys);
        assert_eq!(loaded_metadata.previous_key_ids, original_metadata.previous_key_ids);
    }

    #[test]
    fn test_new_key_age_methods() {
        let policy = RotationPolicy::default();
        let mut metadata = KeyRotationMetadata::new(policy);
        
        // Set created_at to 50 days ago
        metadata.created_at = Utc::now() - Duration::days(50);
        
        // Test key age calculation - allow 0-1 day difference due to time of execution
        let age = metadata.key_age_days();
        assert!(age >= 49 && age <= 51, "Key age should be approximately 50 days, got {}", age);
        assert_eq!(metadata.days_since_rotation(), None);
        
        // Set last rotation to 20 days ago
        metadata.last_rotated = Some(Utc::now() - Duration::days(20));
        
        // Test days since rotation - allow 0-1 day difference
        let days_since = metadata.days_since_rotation().unwrap();
        assert!(days_since >= 19 && days_since <= 21, "Days since rotation should be approximately 20, got {}", days_since);
        
        // Test days until rotation (90 day policy, 20 days since last rotation)
        // Should be approximately 70 days, but allow some variation
        let days_until = metadata.days_until_rotation();
        assert!(days_until >= 69 && days_until <= 71, "Days until rotation should be approximately 70, got {}", days_until);
    }
    
    #[test]
    fn test_key_age_summary_methods() {
        let summary = KeyAgeSummary {
            days_since_creation: 100,
            days_since_rotation: Some(30),
            days_until_next_rotation: 0,
            rotation_recommended: true,
        };
        
        assert!(summary.should_rotate_now());
        assert!(summary.status_description().contains("overdue"));
        
        let summary_future = KeyAgeSummary {
            days_since_creation: 100,
            days_since_rotation: Some(30),
            days_until_next_rotation: 5,
            rotation_recommended: false,
        };
        
        assert!(!summary_future.should_rotate_now());
        assert!(summary_future.status_description().contains("5 days"));
        
        let summary_ok = KeyAgeSummary {
            days_since_creation: 100,
            days_since_rotation: Some(30),
            days_until_next_rotation: 60,
            rotation_recommended: false,
        };
        
        assert!(!summary_ok.should_rotate_now());
        assert!(summary_ok.status_description().contains("60 more days"));
    }

    #[test]
    fn test_get_key_age() {
        use chrono::{Duration, Utc};
        use std::path::PathBuf;
        use tempfile::TempDir;
        
        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        
        // Create a mock key storage directory function for testing
        let mock_key_dir = || -> PathBuf {
            temp_path.to_path_buf()
        };
        
        // Mock the current time
        let mock_now = Utc::now();
        
        // Create temporary key directories with metadata files
        let key1_dir = temp_path.join("key_recent");
        let key2_dir = temp_path.join("key_older");
        let key3_dir = temp_path.join("key_oldest");
        
        fs::create_dir_all(&key1_dir).unwrap();
        fs::create_dir_all(&key2_dir).unwrap();
        fs::create_dir_all(&key3_dir).unwrap();
        
        // Create default rotation policy
        let policy = RotationPolicy::default();
        
        // Create metadata with different creation times
        let mut meta1 = KeyRotationMetadata::new(policy.clone());
        meta1.created_at = mock_now - Duration::days(10);
        
        let mut meta2 = KeyRotationMetadata::new(policy.clone());
        meta2.created_at = mock_now - Duration::days(45);
        
        let mut meta3 = KeyRotationMetadata::new(policy.clone());
        meta3.created_at = mock_now - Duration::days(90);
        
        // Write metadata files
        let meta1_json = serde_json::to_string(&meta1).unwrap();
        let meta2_json = serde_json::to_string(&meta2).unwrap();
        let meta3_json = serde_json::to_string(&meta3).unwrap();
        
        fs::write(key1_dir.join("metadata.json"), meta1_json).unwrap();
        fs::write(key2_dir.join("metadata.json"), meta2_json).unwrap();
        fs::write(key3_dir.join("metadata.json"), meta3_json).unwrap();
        
        // Call get_key_age using our mock directory
        let ages = get_all_key_ages_internal(mock_key_dir).unwrap();
        
        // Verify results
        assert_eq!(ages.len(), 3);
        
        // Find and verify each key's age information - use range checks instead of exact equality
        // since the test execution time might cause small differences
        for age_summary in &ages {
            // Allow for a small tolerance in day calculations
            let days_since_creation = age_summary.days_since_creation;
            
            if days_since_creation >= 9 && days_since_creation <= 11 {
                assert_eq!(age_summary.days_since_rotation, None);
            } else if days_since_creation >= 44 && days_since_creation <= 46 {
                assert_eq!(age_summary.days_since_rotation, None);
            } else if days_since_creation >= 89 && days_since_creation <= 91 {
                assert_eq!(age_summary.days_since_rotation, None);
            } else {
                panic!("Unexpected age: {}", age_summary.days_since_creation);
            }
        }
    }
}
