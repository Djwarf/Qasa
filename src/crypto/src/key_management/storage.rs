// Key storage implementation
// This file contains code moved from src/key_management.rs for key storage

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::aes;
use crate::dilithium::DilithiumKeyPair;
use crate::error::CryptoError;
use crate::key_management::password::derive_key_from_password;
use crate::kyber::KyberKeyPair;

/// Metadata for stored key files
#[derive(Serialize, Deserialize)]
struct KeyMetadata {
    /// Version of the key storage format
    version: u8,
    /// Unique identifier for this key
    key_id: String,
    /// Type of key (Kyber or Dilithium)
    key_type: KeyType,
    /// Creation timestamp (seconds since UNIX epoch)
    created_at: u64,
    /// Last rotation timestamp (seconds since UNIX epoch)
    last_rotated: Option<u64>,
    /// Salt used for password derivation
    password_salt: Vec<u8>,
}

/// Type of cryptographic key
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum KeyType {
    Kyber,
    Dilithium,
}

/// Wrapped key with encryption for storage
#[derive(Serialize, Deserialize)]
struct EncryptedKeyData {
    /// Metadata about the key
    metadata: KeyMetadata,
    /// Encrypted key material
    encrypted_data: Vec<u8>,
    /// Encryption nonce
    nonce: Vec<u8>,
}

/// Get the default directory for key storage
pub fn get_key_storage_directory() -> PathBuf {
    let mut dir = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push("qasa");
    dir.push("keys");
    dir
}

/// Ensure the key storage directory exists
fn ensure_key_directory(dir: Option<&Path>) -> Result<PathBuf, CryptoError> {
    let path = match dir {
        Some(d) => d.to_path_buf(),
        None => get_key_storage_directory(),
    };

    if !path.exists() {
        fs::create_dir_all(&path).map_err(|e| {
            CryptoError::KeyManagementError(format!("Failed to create key directory: {}", e))
        })?;
    }

    Ok(path)
}

/// Generate a unique key ID
fn generate_key_id() -> String {
    use uuid::Uuid;
    Uuid::new_v4().to_string()
}

/// Get the current time in seconds since UNIX epoch
fn current_time_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Stores a Kyber key pair to disk
///
/// # Arguments
///
/// * `keypair` - The KyberKeyPair to store
/// * `path` - Path where to store the key (or None for default)
/// * `password` - Password to encrypt the key with
///
/// # Returns
///
/// `Ok(())` if successful, or an error
pub fn store_kyber_keypair(
    keypair: &KyberKeyPair,
    path: Option<&str>,
    password: &str,
) -> Result<String, CryptoError> {
    // Serialize the key pair
    let key_data = bincode::serialize(keypair)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to serialize key pair: {}", e)))?;
    
    // Generate a key ID
    let key_id = generate_key_id();
    
    // Derive encryption key from password
    let derived_key = derive_key_from_password(password, None, None)?;
    let key_bytes = derived_key.key.clone(); // Clone to avoid borrowing issues
    let salt = derived_key.salt.clone(); // Clone to avoid borrowing issues
    
    // Encrypt the key data
    let (encrypted_data, nonce) = aes::encrypt(&key_data, &key_bytes, None)?;
    
    // Create metadata
    let metadata = KeyMetadata {
        version: 1,
        key_id: key_id.clone(),
        key_type: KeyType::Kyber,
        created_at: current_time_secs(),
        last_rotated: None,
        password_salt: salt,
    };
    
    // Create encrypted key structure
    let encrypted_key = EncryptedKeyData {
        metadata,
        encrypted_data,
        nonce,
    };
    
    // Serialize the encrypted key
    let serialized = bincode::serialize(&encrypted_key)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to serialize encrypted key: {}", e)))?;
    
    // Get/create key directory
    let key_directory = ensure_key_directory(path.map(Path::new))?;
    
    // Write to file
    let file_path = key_directory.join(format!("{}.kyber.key", key_id));
    let mut file = File::create(&file_path).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to create key file: {}", e))
    })?;
    
    file.write_all(&serialized).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to write key file: {}", e))
    })?;
    
    Ok(key_id)
}

/// Loads a Kyber key pair from disk
///
/// # Arguments
///
/// * `key_id` - ID of the key to load
/// * `password` - Password to decrypt the key with
///
/// # Returns
///
/// The loaded KyberKeyPair or an error
pub fn load_kyber_keypair(
    key_id: &str,
    password: &str,
) -> Result<KyberKeyPair, CryptoError> {
    let key_directory = ensure_key_directory(None)?;
    let file_path = key_directory.join(format!("{}.kyber.key", key_id));
    
    // Check if file exists
    if !file_path.exists() {
        return Err(CryptoError::KeyManagementError(
            format!("Key {} does not exist", key_id),
        ));
    }
    
    // Read the encrypted key file
    let mut file = File::open(&file_path).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to open key file: {}", e))
    })?;
    
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to read key file: {}", e))
    })?;
    
    // Deserialize the encrypted key structure
    let encrypted_key: EncryptedKeyData = bincode::deserialize(&encrypted_data)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize key file: {}", e)))?;
    
    // Derive the decryption key from the password
    let derived_key = derive_key_from_password(password, Some(&encrypted_key.metadata.password_salt), None)?;
    let key_bytes = derived_key.key.clone(); // Clone to avoid borrowing issues
    
    // Decrypt the key data
    let key_data = aes::decrypt(
        &encrypted_key.encrypted_data,
        &key_bytes,
        &encrypted_key.nonce,
        None,
    )?;
    
    // Deserialize the key pair
    let keypair: KyberKeyPair = bincode::deserialize(&key_data)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize key data: {}", e)))?;
    
    Ok(keypair)
}

/// Stores a Dilithium key pair to disk
///
/// # Arguments
///
/// * `keypair` - The DilithiumKeyPair to store
/// * `path` - Path where to store the key (or None for default)
/// * `password` - Password to encrypt the key with
///
/// # Returns
///
/// `Ok(key_id)` if successful with the generated key ID, or an error
pub fn store_dilithium_keypair(
    keypair: &DilithiumKeyPair,
    path: Option<&str>,
    password: &str,
) -> Result<String, CryptoError> {
    // Serialize the key pair
    let key_data = bincode::serialize(keypair)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to serialize key pair: {}", e)))?;
    
    // Generate a key ID
    let key_id = generate_key_id();
    
    // Derive encryption key from password
    let derived_key = derive_key_from_password(password, None, None)?;
    let key_bytes = derived_key.key.clone(); // Clone to avoid borrowing issues
    let salt = derived_key.salt.clone(); // Clone to avoid borrowing issues
    
    // Encrypt the key data
    let (encrypted_data, nonce) = aes::encrypt(&key_data, &key_bytes, None)?;
    
    // Create metadata
    let metadata = KeyMetadata {
        version: 1,
        key_id: key_id.clone(),
        key_type: KeyType::Dilithium,
        created_at: current_time_secs(),
        last_rotated: None,
        password_salt: salt,
    };
    
    // Create encrypted key structure
    let encrypted_key = EncryptedKeyData {
        metadata,
        encrypted_data,
        nonce,
    };
    
    // Serialize the encrypted key
    let serialized = bincode::serialize(&encrypted_key)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to serialize encrypted key: {}", e)))?;
    
    // Get/create key directory
    let key_directory = ensure_key_directory(path.map(Path::new))?;
    
    // Write to file
    let file_path = key_directory.join(format!("{}.dilithium.key", key_id));
    let mut file = File::create(&file_path).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to create key file: {}", e))
    })?;
    
    file.write_all(&serialized).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to write key file: {}", e))
    })?;
    
    Ok(key_id)
}

/// Loads a Dilithium key pair from disk
///
/// # Arguments
///
/// * `key_id` - ID of the key to load
/// * `password` - Password to decrypt the key with
///
/// # Returns
///
/// The loaded DilithiumKeyPair or an error
pub fn load_dilithium_keypair(
    key_id: &str,
    password: &str,
) -> Result<DilithiumKeyPair, CryptoError> {
    let key_directory = ensure_key_directory(None)?;
    let file_path = key_directory.join(format!("{}.dilithium.key", key_id));
    
    // Check if file exists
    if !file_path.exists() {
        return Err(CryptoError::KeyManagementError(
            format!("Key {} does not exist", key_id),
        ));
    }
    
    // Read the encrypted key file
    let mut file = File::open(&file_path).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to open key file: {}", e))
    })?;
    
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to read key file: {}", e))
    })?;
    
    // Deserialize the encrypted key structure
    let encrypted_key: EncryptedKeyData = bincode::deserialize(&encrypted_data)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize key file: {}", e)))?;
    
    // Derive the decryption key from the password
    let derived_key = derive_key_from_password(password, Some(&encrypted_key.metadata.password_salt), None)?;
    let key_bytes = derived_key.key.clone(); // Clone to avoid borrowing issues
    
    // Decrypt the key data
    let key_data = aes::decrypt(
        &encrypted_key.encrypted_data,
        &key_bytes,
        &encrypted_key.nonce,
        None,
    )?;
    
    // Deserialize the key pair
    let keypair: DilithiumKeyPair = bincode::deserialize(&key_data)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize key data: {}", e)))?;
    
    Ok(keypair)
}

/// List all stored keys
///
/// # Returns
///
/// A vector of tuples containing (key_id, key_type) for all stored keys
pub fn list_keys() -> Result<Vec<(String, String)>, CryptoError> {
    let key_directory = ensure_key_directory(None)?;
    
    let entries = fs::read_dir(&key_directory).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to read key directory: {}", e))
    })?;
    
    let mut keys = Vec::new();
    
    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.is_file() {
                if let Some(file_name) = path.file_name() {
                    if let Some(file_name_str) = file_name.to_str() {
                        if file_name_str.ends_with(".kyber.key") {
                            let key_id = file_name_str.replace(".kyber.key", "");
                            keys.push((key_id, "kyber".to_string()));
                        } else if file_name_str.ends_with(".dilithium.key") {
                            let key_id = file_name_str.replace(".dilithium.key", "");
                            keys.push((key_id, "dilithium".to_string()));
                        }
                    }
                }
            }
        }
    }
    
    Ok(keys)
}

/// Delete a stored key
///
/// # Arguments
///
/// * `key_id` - ID of the key to delete
/// * `key_type` - Type of the key ("kyber" or "dilithium")
///
/// # Returns
///
/// `Ok(())` if successful, or an error
pub fn delete_key(key_id: &str, key_type: &str) -> Result<(), CryptoError> {
    let key_directory = ensure_key_directory(None)?;
    
    let file_name = match key_type.to_lowercase().as_str() {
        "kyber" => format!("{}.kyber.key", key_id),
        "dilithium" => format!("{}.dilithium.key", key_id),
        _ => return Err(CryptoError::InvalidParameterError(
            format!("Invalid key type: {}", key_type),
        )),
    };
    
    let file_path = key_directory.join(file_name);
    
    if !file_path.exists() {
        return Err(CryptoError::KeyManagementError(
            format!("Key {} of type {} does not exist", key_id, key_type),
        ));
    }
    
    fs::remove_file(&file_path).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to delete key file: {}", e))
    })?;
    
    Ok(())
}

/// Exports a stored key to a file
///
/// # Arguments
///
/// * `key_id` - ID of the key to export
/// * `key_type` - Type of key ("kyber" or "dilithium")
/// * `password` - Password used to decrypt the stored key
/// * `export_password` - Password to encrypt the exported key with
/// * `export_path` - Path where to save the exported key
///
/// # Returns
///
/// `Ok(())` if successful, or an error
pub fn export_key(
    key_id: &str,
    key_type: &str,
    password: &str,
    export_password: &str,
    export_path: &str,
) -> Result<(), CryptoError> {
    let key_directory = ensure_key_directory(None)?;
    
    // Construct file path based on key type
    let file_name = match key_type.to_lowercase().as_str() {
        "kyber" => format!("{}.kyber.key", key_id),
        "dilithium" => format!("{}.dilithium.key", key_id),
        _ => return Err(CryptoError::KeyManagementError(format!("Invalid key type: {}", key_type))),
    };
    
    let file_path = key_directory.join(file_name);
    
    // Read the encrypted key file
    let mut file = File::open(&file_path).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to open key file: {}", e))
    })?;
    
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to read key file: {}", e))
    })?;
    
    // Deserialize the encrypted key structure
    let encrypted_key: EncryptedKeyData = bincode::deserialize(&encrypted_data)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize key file: {}", e)))?;
    
    // Derive the decryption key from the password
    let derived_key = derive_key_from_password(password, Some(&encrypted_key.metadata.password_salt), None)?;
    
    // Decrypt the key data
    let key_data = aes::decrypt(
        &encrypted_key.encrypted_data,
        &derived_key.key,
        &encrypted_key.nonce,
        None,
    )?;
    
    // Now re-encrypt with the export password
    let export_derived_key = derive_key_from_password(export_password, None, None)?;
    let export_key_bytes = export_derived_key.key.clone(); // Clone to avoid borrowing issues
    let export_salt = export_derived_key.salt.clone(); // Clone to avoid borrowing issues
    
    let (re_encrypted_data, export_nonce) = aes::encrypt(&key_data, &export_key_bytes, None)?;
    
    // Create export metadata
    let export_metadata = KeyMetadata {
        version: encrypted_key.metadata.version,
        key_id: encrypted_key.metadata.key_id.clone(),
        key_type: encrypted_key.metadata.key_type,
        created_at: encrypted_key.metadata.created_at,
        last_rotated: encrypted_key.metadata.last_rotated,
        password_salt: export_salt,
    };
    
    // Create the export structure
    let export_key = EncryptedKeyData {
        metadata: export_metadata,
        encrypted_data: re_encrypted_data,
        nonce: export_nonce,
    };
    
    // Serialize the export key
    let export_data = bincode::serialize(&export_key)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to serialize exported key: {}", e)))?;
    
    // Write to export file
    let mut file = File::create(export_path).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to create export file: {}", e))
    })?;
    
    file.write_all(&export_data).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to write export data: {}", e))
    })?;
    
    Ok(())
}

/// Imports a key from a file
///
/// # Arguments
///
/// * `import_path` - Path to the exported key file
/// * `import_password` - Password used when exporting the key
/// * `new_password` - New password to use for storing the key
///
/// # Returns
///
/// A tuple with the new key ID and key type if successful, or an error
pub fn import_key(
    import_path: &str,
    import_password: &str,
    new_password: &str,
) -> Result<(String, String), CryptoError> {
    // Read the export file
    let mut file = File::open(import_path).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to open import file: {}", e))
    })?;
    
    let mut import_data = Vec::new();
    file.read_to_end(&mut import_data).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to read import file: {}", e))
    })?;
    
    // Deserialize the import data
    let imported_key: EncryptedKeyData = bincode::deserialize(&import_data)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize import file: {}", e)))?;
    
    // Derive the decryption key from the import password
    let import_derived_key = derive_key_from_password(import_password, Some(&imported_key.metadata.password_salt), None)?;
    
    // Decrypt the key data
    let key_data = aes::decrypt(
        &imported_key.encrypted_data,
        &import_derived_key.key,
        &imported_key.nonce,
        None,
    )?;
    
    // Generate a new key ID
    let new_key_id = generate_key_id();
    
    // Re-encrypt with the new password
    let new_derived_key = derive_key_from_password(new_password, None, None)?;
    let new_key_bytes = new_derived_key.key.clone(); // Clone to avoid borrowing issues
    let new_salt = new_derived_key.salt.clone(); // Clone to avoid borrowing issues
    
    let (re_encrypted_data, new_nonce) = aes::encrypt(&key_data, &new_key_bytes, None)?;
    
    // Create new metadata
    let new_metadata = KeyMetadata {
        version: imported_key.metadata.version,
        key_id: new_key_id.clone(),
        key_type: imported_key.metadata.key_type,
        created_at: current_time_secs(),  // Use current time for import
        last_rotated: None,  // Reset rotation
        password_salt: new_salt,
    };
    
    // Create the new key structure
    let new_key = EncryptedKeyData {
        metadata: new_metadata,
        encrypted_data: re_encrypted_data,
        nonce: new_nonce,
    };
    
    // Serialize the new key
    let new_key_data = bincode::serialize(&new_key)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to serialize new key: {}", e)))?;
    
    // Determine key type string for file name
    let key_type_str = match imported_key.metadata.key_type {
        KeyType::Kyber => "kyber",
        KeyType::Dilithium => "dilithium",
    };
    
    // Ensure directory exists
    let key_directory = ensure_key_directory(None)?;
    
    // Write to new file
    let file_path = key_directory.join(format!("{}.{}.key", new_key_id, key_type_str));
    let mut file = File::create(&file_path).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to create new key file: {}", e))
    })?;
    
    file.write_all(&new_key_data).map_err(|e| {
        CryptoError::KeyManagementError(format!("Failed to write new key data: {}", e))
    })?;
    
    Ok((new_key_id, key_type_str.to_string()))
}
