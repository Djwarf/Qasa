use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::kyber::{KyberKeyPair, KyberVariant};
use crate::utils;

/// The key store manager for securely storing cryptographic keys
pub struct KeyManager {
    store_path: PathBuf,
    keys: Arc<Mutex<HashMap<String, EncryptedKeyData>>>,
    loaded: bool,
}

/// Key types supported by the key manager
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    /// CRYSTALS-Kyber key
    Kyber,
    /// CRYSTALS-Dilithium key
    Dilithium,
    /// Other key type
    Other(String),
}

/// Encrypted key data for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedKeyData {
    /// Key type
    key_type: KeyType,
    /// Encrypted key data
    encrypted_data: Vec<u8>,
    /// Nonce used for encryption
    nonce: Vec<u8>,
    /// Salt used for key derivation
    salt: Vec<u8>,
    /// Created timestamp (seconds since epoch)
    created_at: u64,
    /// Last modified timestamp (seconds since epoch)
    modified_at: u64,
    /// Key metadata
    metadata: HashMap<String, String>,
}

/// Key store file format
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyStore {
    /// Version of the key store format
    version: u8,
    /// Encrypted keys
    keys: HashMap<String, EncryptedKeyData>,
}

impl KeyManager {
    /// Create a new key manager with the given store path
    pub fn new<P: AsRef<Path>>(store_path: P) -> Self {
        let store_path = store_path.as_ref().to_path_buf();
        
        Self {
            store_path,
            keys: Arc::new(Mutex::new(HashMap::new())),
            loaded: false,
        }
    }
    
    /// Initialize the key manager and load the key store
    pub fn init(&mut self) -> Result<(), CryptoError> {
        self.load_keys()?;
        self.loaded = true;
        Ok(())
    }
    
    /// Load keys from the key store file
    fn load_keys(&mut self) -> Result<(), CryptoError> {
        if !self.store_path.exists() {
            // Create directory if it doesn't exist
            if let Some(parent) = self.store_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| CryptoError::IoError(e))?;
            }
            
            // Create empty key store
            let store = KeyStore {
                version: 1,
                keys: HashMap::new(),
            };
            
            let serialized = serde_json::to_string_pretty(&store)
                .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
                
            let mut file = File::create(&self.store_path)
                .map_err(|e| CryptoError::IoError(e))?;
                
            file.write_all(serialized.as_bytes())
                .map_err(|e| CryptoError::IoError(e))?;
                
            return Ok(());
        }
        
        // Read the file
        let mut file = File::open(&self.store_path)
            .map_err(|e| CryptoError::IoError(e))?;
            
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| CryptoError::IoError(e))?;
            
        // Parse the file
        let store: KeyStore = serde_json::from_str(&contents)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
            
        // Update our keys
        let mut keys = self.keys.lock().unwrap();
        *keys = store.keys;
        
        Ok(())
    }
    
    /// Save keys to the key store file
    fn save_keys(&self) -> Result<(), CryptoError> {
        let keys = self.keys.lock().unwrap();
        
        let store = KeyStore {
            version: 1,
            keys: keys.clone(),
        };
        
        let serialized = serde_json::to_string_pretty(&store)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
            
        let mut file = File::create(&self.store_path)
            .map_err(|e| CryptoError::IoError(e))?;
            
        file.write_all(serialized.as_bytes())
            .map_err(|e| CryptoError::IoError(e))?;
            
        Ok(())
    }
    
    /// Derive an encryption key from a password
    fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Create a key derivation function using HMAC-SHA256 with the salt
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let derived_key = hasher.finalize();
        
        // Return the first 32 bytes as the encryption key
        Ok(derived_key[..32].to_vec())
    }
    
    /// Store a Kyber key pair in the key store
    pub fn store_kyber_key(&self, name: &str, key_pair: &KyberKeyPair, password: &str) -> Result<(), CryptoError> {
        if !self.loaded {
            return Err(CryptoError::KeyManagementError(
                "Key manager not initialized".to_string()
            ));
        }
        
        // Serialize the key pair
        let key_data = key_pair.to_bytes()?;
        
        // Generate a random salt
        let salt = utils::random_bytes(16)?;
        
        // Derive encryption key from password
        let encryption_key = Self::derive_key_from_password(password, &salt)?;
        
        // Encrypt the key data
        let key = Key::from_slice(&encryption_key[0..32]);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let encrypted_data = cipher.encrypt(&nonce, key_data.as_ref())
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
            
        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert("algorithm".to_string(), key_pair.algorithm.to_string());
        metadata.insert("public_key_size".to_string(), key_pair.public_key.len().to_string());
        
        // Get current timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CryptoError::KeyManagementError(e.to_string()))?
            .as_secs();
            
        // Create the encrypted key data
        let encrypted_key = EncryptedKeyData {
            key_type: KeyType::Kyber,
            encrypted_data,
            nonce: nonce.to_vec(),
            salt,
            created_at: now,
            modified_at: now,
            metadata,
        };
        
        // Store the key
        let mut keys = self.keys.lock().unwrap();
        keys.insert(name.to_string(), encrypted_key);
        
        // Save to disk
        drop(keys); // Release the lock before saving
        self.save_keys()?;
        
        Ok(())
    }
    
    /// Load a Kyber key pair from the key store
    pub fn load_kyber_key(&self, name: &str, password: &str) -> Result<KyberKeyPair, CryptoError> {
        if !self.loaded {
            return Err(CryptoError::KeyManagementError(
                "Key manager not initialized".to_string()
            ));
        }
        
        // Get the encrypted key data
        let keys = self.keys.lock().unwrap();
        let encrypted_key = keys.get(name)
            .ok_or_else(|| CryptoError::KeyManagementError(
                format!("Key '{}' not found", name)
            ))?;
            
        // Check key type
        if encrypted_key.key_type != KeyType::Kyber {
            return Err(CryptoError::KeyManagementError(
                format!("Key '{}' is not a Kyber key", name)
            ));
        }
        
        // Derive encryption key from password
        let encryption_key = Self::derive_key_from_password(password, &encrypted_key.salt)?;
        
        // Decrypt the key data
        let key = Key::from_slice(&encryption_key[0..32]);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&encrypted_key.nonce);
        
        let decrypted_data = cipher.decrypt(nonce, encrypted_key.encrypted_data.as_ref())
            .map_err(|e| CryptoError::DecryptionError(
                format!("Failed to decrypt key '{}': {}", name, e)
            ))?;
            
        // Deserialize the key pair
        let key_pair = KyberKeyPair::from_bytes(&decrypted_data)?;
        
        Ok(key_pair)
    }
    
    /// Delete a key from the key store
    pub fn delete_key(&self, name: &str) -> Result<(), CryptoError> {
        if !self.loaded {
            return Err(CryptoError::KeyManagementError(
                "Key manager not initialized".to_string()
            ));
        }
        
        // Remove the key
        let mut keys = self.keys.lock().unwrap();
        if keys.remove(name).is_none() {
            return Err(CryptoError::KeyManagementError(
                format!("Key '{}' not found", name)
            ));
        }
        
        // Save to disk
        drop(keys); // Release the lock before saving
        self.save_keys()?;
        
        Ok(())
    }
    
    /// List all keys in the key store
    pub fn list_keys(&self) -> Result<Vec<(String, KeyType)>, CryptoError> {
        if !self.loaded {
            return Err(CryptoError::KeyManagementError(
                "Key manager not initialized".to_string()
            ));
        }
        
        let keys = self.keys.lock().unwrap();
        let mut result = Vec::new();
        
        for (name, key_data) in keys.iter() {
            result.push((name.clone(), key_data.key_type.clone()));
        }
        
        Ok(result)
    }
    
    /// Check if a key exists in the key store
    pub fn has_key(&self, name: &str) -> bool {
        if !self.loaded {
            return false;
        }
        
        let keys = self.keys.lock().unwrap();
        keys.contains_key(name)
    }
    
    /// Rotate a Kyber key
    pub fn rotate_kyber_key(&self, name: &str, password: &str) -> Result<KyberKeyPair, CryptoError> {
        if !self.loaded {
            return Err(CryptoError::KeyManagementError(
                "Key manager not initialized".to_string()
            ));
        }
        
        // Load the old key to get its algorithm
        let old_key = self.load_kyber_key(name, password)?;
        
        // Generate a new key with the same algorithm
        let new_key = KyberKeyPair::generate(old_key.algorithm)?;
        
        // Store the new key
        self.store_kyber_key(name, &new_key, password)?;
        
        Ok(new_key)
    }
}

/// Convenience function to get the default key manager directory
pub fn default_key_dir() -> PathBuf {
    let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push(".qasa");
    path.push("keys");
    path.push("keystore.json");
    path
}

/// Initialize the default key manager
pub fn init_default_key_manager() -> Result<KeyManager, CryptoError> {
    let key_dir = default_key_dir();
    let mut manager = KeyManager::new(key_dir);
    manager.init()?;
    Ok(manager)
}

/// Store a key with the default key manager
pub fn store_key(name: &str, key_pair: &KyberKeyPair, password: &str) -> Result<(), CryptoError> {
    let manager = init_default_key_manager()?;
    manager.store_kyber_key(name, key_pair, password)
}

/// Load a key with the default key manager
pub fn load_key(name: &str, password: &str) -> Result<KyberKeyPair, CryptoError> {
    let manager = init_default_key_manager()?;
    manager.load_kyber_key(name, password)
}

/// Delete a key with the default key manager
pub fn delete_key(name: &str) -> Result<(), CryptoError> {
    let manager = init_default_key_manager()?;
    manager.delete_key(name)
}

/// List keys with the default key manager
pub fn list_keys() -> Result<Vec<(String, KeyType)>, CryptoError> {
    let manager = init_default_key_manager()?;
    manager.list_keys()
}

/// Rotate a key with the default key manager
pub fn rotate_key(name: &str, password: &str) -> Result<KyberKeyPair, CryptoError> {
    let manager = init_default_key_manager()?;
    manager.rotate_kyber_key(name, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_key_manager_store_load() {
        // Create a temporary directory for the key store
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test_keystore.json");
        
        // Create a key manager
        let mut manager = KeyManager::new(key_path);
        manager.init().unwrap();
        
        // Generate a key pair
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        
        // Store the key
        manager.store_kyber_key("test_key", &key_pair, "password123").unwrap();
        
        // Load the key
        let loaded_key = manager.load_kyber_key("test_key", "password123").unwrap();
        
        // Verify the key was loaded correctly
        assert_eq!(key_pair.algorithm, loaded_key.algorithm);
        assert_eq!(key_pair.public_key, loaded_key.public_key);
        assert_eq!(key_pair.secret_key, loaded_key.secret_key);
    }
    
    #[test]
    fn test_key_manager_wrong_password() {
        // Create a temporary directory for the key store
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test_keystore.json");
        
        // Create a key manager
        let mut manager = KeyManager::new(key_path);
        manager.init().unwrap();
        
        // Generate a key pair
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        
        // Store the key
        manager.store_kyber_key("test_key", &key_pair, "password123").unwrap();
        
        // Try to load with wrong password
        let result = manager.load_kyber_key("test_key", "wrong_password");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_key_manager_delete() {
        // Create a temporary directory for the key store
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test_keystore.json");
        
        // Create a key manager
        let mut manager = KeyManager::new(key_path);
        manager.init().unwrap();
        
        // Generate a key pair
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        
        // Store the key
        manager.store_kyber_key("test_key", &key_pair, "password123").unwrap();
        
        // Check the key exists
        assert!(manager.has_key("test_key"));
        
        // Delete the key
        manager.delete_key("test_key").unwrap();
        
        // Check the key is gone
        assert!(!manager.has_key("test_key"));
    }
    
    #[test]
    fn test_key_manager_list() {
        // Create a temporary directory for the key store
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test_keystore.json");
        
        // Create a key manager
        let mut manager = KeyManager::new(key_path);
        manager.init().unwrap();
        
        // Store a few keys
        let key_pair1 = KyberKeyPair::generate(KyberVariant::Kyber512).unwrap();
        let key_pair2 = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        
        manager.store_kyber_key("key1", &key_pair1, "password").unwrap();
        manager.store_kyber_key("key2", &key_pair2, "password").unwrap();
        
        // List keys
        let keys = manager.list_keys().unwrap();
        
        // Check keys are listed
        assert_eq!(keys.len(), 2);
        
        // Check key names and types
        let mut found_key1 = false;
        let mut found_key2 = false;
        
        for (name, key_type) in keys {
            if name == "key1" {
                assert_eq!(key_type, KeyType::Kyber);
                found_key1 = true;
            } else if name == "key2" {
                assert_eq!(key_type, KeyType::Kyber);
                found_key2 = true;
            }
        }
        
        assert!(found_key1);
        assert!(found_key2);
    }
    
    #[test]
    fn test_key_rotation() {
        // Create a temporary directory for the key store
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test_keystore.json");
        
        // Create a key manager
        let mut manager = KeyManager::new(key_path);
        manager.init().unwrap();
        
        // Generate a key pair
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        
        // Store the key
        manager.store_kyber_key("rotate_key", &key_pair, "password123").unwrap();
        
        // Rotate the key
        let new_key = manager.rotate_kyber_key("rotate_key", "password123").unwrap();
        
        // Verify the new key is different
        assert_ne!(key_pair.public_key, new_key.public_key);
        assert_ne!(key_pair.secret_key, new_key.secret_key);
        
        // Verify the new key has the same algorithm
        assert_eq!(key_pair.algorithm, new_key.algorithm);
        
        // Load the key to verify it was stored correctly
        let loaded_key = manager.load_kyber_key("rotate_key", "password123").unwrap();
        
        // Verify the loaded key matches the new key
        assert_eq!(new_key.public_key, loaded_key.public_key);
        assert_eq!(new_key.secret_key, loaded_key.secret_key);
    }
} 