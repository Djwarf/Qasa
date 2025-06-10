// Key storage implementation
// This file contains code moved from src/key_management.rs for key storage

use super::password::derive_key_from_password;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::aes;
use crate::dilithium::DilithiumKeyPair;
use crate::error::CryptoError;
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
            CryptoError::key_management_error("Failed to create key directory", &format!("Directory creation failed: {}", e), "unknown")
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
        CryptoError::key_management_error("Failed to create key file", &format!("File creation error: {}", e), "unknown")
    })?;
    
    file.write_all(&serialized).map_err(|e| {
        CryptoError::key_management_error("Failed to write key file", &format!("File write error: {}", e), "unknown")
    })?;
    
    Ok(key_id)
}

/// Loads a Kyber key pair from disk
///
/// # Arguments
///
/// * `key_id` - ID of the key to load
/// * `password` - Password to decrypt the key with
/// * `path` - Optional path to the key storage directory
///
/// # Returns
///
/// The loaded KyberKeyPair or an error
pub fn load_kyber_keypair(
    key_id: &str,
    password: &str,
    path: Option<&str>,
) -> Result<KyberKeyPair, CryptoError> {
    let key_directory = ensure_key_directory(path.map(Path::new))?;
    let file_path = key_directory.join(format!("{}.kyber.key", key_id));
    
    // Check if file exists
    if !file_path.exists() {
        return Err(CryptoError::key_management_error("Key not found", &format!("Key {} does not exist", key_id), "unknown"));
    }
    
    // Read the encrypted key file
    let mut file = File::open(&file_path).map_err(|e| {
        CryptoError::key_management_error("Failed to open key file", &format!("File open error: {}", e), "unknown")
    })?;
    
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data).map_err(|e| {
        CryptoError::key_management_error("Failed to read key file", &format!("File read error: {}", e), "unknown")
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
    let keypair = bincode::deserialize(&key_data)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize key pair: {}", e)))?;
    
    // Securely zero the decrypted data
    use crate::utils::secure_zero;
    secure_zero(&mut encrypted_data);
    
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
        CryptoError::key_management_error("Failed to create key file", &format!("File creation error: {}", e), "unknown")
    })?;
    
    file.write_all(&serialized).map_err(|e| {
        CryptoError::key_management_error("Failed to write key file", &format!("File write error: {}", e), "unknown")
    })?;
    
    Ok(key_id)
}

/// Loads a Dilithium key pair from disk
///
/// # Arguments
///
/// * `key_id` - ID of the key to load
/// * `password` - Password to decrypt the key with
/// * `path` - Optional path to the key storage directory
///
/// # Returns
///
/// The loaded DilithiumKeyPair or an error
pub fn load_dilithium_keypair(
    key_id: &str,
    password: &str,
    path: Option<&str>,
) -> Result<DilithiumKeyPair, CryptoError> {
    let key_directory = ensure_key_directory(path.map(Path::new))?;
    let file_path = key_directory.join(format!("{}.dilithium.key", key_id));
    
    // Check if file exists
    if !file_path.exists() {
        return Err(CryptoError::key_management_error("Key not found", &format!("Key {} does not exist", key_id), "unknown"));
    }
    
    // Read the encrypted key file
    let mut file = File::open(&file_path).map_err(|e| {
        CryptoError::key_management_error("Failed to open key file", &format!("File open error: {}", e), "unknown")
    })?;
    
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data).map_err(|e| {
        CryptoError::key_management_error("Failed to read key file", &format!("File read error: {}", e), "unknown")
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
    let keypair = bincode::deserialize(&key_data)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize key pair: {}", e)))?;
    
    // Securely zero the decrypted data
    use crate::utils::secure_zero;
    secure_zero(&mut encrypted_data);
    
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
        CryptoError::key_management_error("Failed to read key directory", &format!("Directory read error: {}", e), "unknown")
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

/// Deletes a key from storage
///
/// # Arguments
///
/// * `key_id` - ID of the key to delete
/// * `key_type` - Type of key ("kyber" or "dilithium")
/// * `path` - Optional path to the key storage directory
///
/// # Returns
///
/// `Ok(())` if successful, or an error
pub fn delete_key(key_id: &str, key_type: &str, path: Option<&str>) -> Result<(), CryptoError> {
    let key_directory = ensure_key_directory(path.map(Path::new))?;
    
    // Determine file extension based on key type
    let extension = match key_type.to_lowercase().as_str() {
        "kyber" => "kyber.key",
        "dilithium" => "dilithium.key",
        _ => return Err(CryptoError::key_management_error("Operation failed", &format!("Invalid key type: {}", key_type), "unknown")
        )),
    };
    
    let file_path = key_directory.join(format!("{}.{}", key_id, extension));
    
    // Check if file exists
    if !file_path.exists() {
        return Err(CryptoError::key_management_error("Key not found", &format!("Key {} does not exist", key_id), "unknown"));
    }
    
    // Delete the key file
    fs::remove_file(&file_path).map_err(|e| {
        CryptoError::key_management_error("Failed to delete key file", &format!("File deletion error: {}", e), "unknown")
    })?;
    
    // Also delete metadata file if it exists
    let metadata_path = key_directory.join(format!("{}.{}.metadata", key_id, key_type));
    if metadata_path.exists() {
        let _ = fs::remove_file(&metadata_path);
    }
    
    Ok(())
}

/// Exports a key to a file
///
/// # Arguments
///
/// * `key_id` - ID of the key to export
/// * `key_type` - Type of key ("kyber" or "dilithium")
/// * `password` - Password to decrypt the key
/// * `export_password` - Password to encrypt the exported key
/// * `export_path` - Path to export the key to
/// * `key_storage_path` - Optional path to the key storage directory
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
    key_storage_path: Option<&str>,
) -> Result<(), CryptoError> {
    // Determine key type and load the key
    let key_data = match key_type.to_lowercase().as_str() {
        "kyber" => {
            let keypair = load_kyber_keypair(key_id, password, key_storage_path)?;
            bincode::serialize(&keypair).map_err(|e| {
                CryptoError::SerializationError(format!("Failed to serialize keypair: {}", e))
            })?
        },
        "dilithium" => {
            let keypair = load_dilithium_keypair(key_id, password, key_storage_path)?;
            bincode::serialize(&keypair).map_err(|e| {
                CryptoError::SerializationError(format!("Failed to serialize keypair: {}", e))
            })?
        },
        _ => return Err(CryptoError::key_management_error("Operation failed", &format!("Invalid key type: {}", key_type), "unknown")),
    };
    
    // Derive a key from the export password
    let derived_key = derive_key_from_password(export_password, None, None)?;
    let key_bytes = derived_key.key.clone();
    
    // Create export metadata
    #[derive(Serialize, Deserialize)]
    struct ExportMetadata {
        version: u8,
        key_id: String,
        key_type: String,
        export_date: u64,
        salt: Vec<u8>,
    }
    
    let metadata = ExportMetadata {
        version: 1,
        key_id: key_id.to_string(),
        key_type: key_type.to_string(),
        export_date: current_time_secs(),
        salt: derived_key.salt.clone(),
    };
    
    // Encrypt the key data
    let (encrypted_data, nonce) = aes::encrypt(&key_data, &key_bytes, None)?;
    
    // Create export structure
    #[derive(Serialize, Deserialize)]
    struct ExportedKey {
        metadata: ExportMetadata,
        encrypted_data: Vec<u8>,
        nonce: Vec<u8>,
    }
    
    let exported_key = ExportedKey {
        metadata,
        encrypted_data,
        nonce,
    };
    
    // Serialize the export structure
    let serialized = bincode::serialize(&exported_key)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to serialize exported key: {}", e)))?;
    
    // Write to file
    let mut file = File::create(export_path).map_err(|e| {
        CryptoError::key_management_error("Failed to create export file", &format!("Export file creation error: {}", e), "unknown")
    })?;
    
    file.write_all(&serialized).map_err(|e| {
        CryptoError::key_management_error("Failed to write export file", &format!("File write error: {}", e), "unknown")
    })?;
    
    Ok(())
}

/// Imports a key from a file
///
/// # Arguments
///
/// * `import_path` - Path to the file to import
/// * `import_password` - Password to decrypt the imported key
/// * `new_password` - Password to encrypt the key for storage
/// * `key_storage_path` - Optional path to the key storage directory
///
/// # Returns
///
/// A tuple with the new key's ID and type, or an error
pub fn import_key(
    import_path: &str,
    import_password: &str,
    new_password: &str,
    key_storage_path: Option<&str>,
) -> Result<(String, String), CryptoError> {
    // Read the exported key file
    let mut file = File::open(import_path).map_err(|e| {
        CryptoError::key_management_error("Failed to open export file", &format!("File open error: {}", e), "unknown")
    })?;
    
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data).map_err(|e| {
        CryptoError::key_management_error("Failed to read export file", &format!("File read error: {}", e), "unknown")
    })?;
    
    // Deserialize the export structure
    #[derive(Serialize, Deserialize)]
    struct ExportMetadata {
        version: u8,
        key_id: String,
        key_type: String,
        export_date: u64,
        salt: Vec<u8>,
    }
    
    #[derive(Serialize, Deserialize)]
    struct ExportedKey {
        metadata: ExportMetadata,
        encrypted_data: Vec<u8>,
        nonce: Vec<u8>,
    }
    
    let exported_key: ExportedKey = bincode::deserialize(&encrypted_data)
        .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize export file: {}", e)))?;
    
    // Derive the decryption key from the import password
    let derived_key = derive_key_from_password(import_password, Some(&exported_key.metadata.salt), None)?;
    let key_bytes = derived_key.key.clone();
    
    // Decrypt the key data
    let key_data = aes::decrypt(
        &exported_key.encrypted_data,
        &key_bytes,
        &exported_key.nonce,
        None,
    )?;
    
    // Store the key based on its type
    let key_type = exported_key.metadata.key_type.to_lowercase();
    let new_key_id = match key_type.as_str() {
        "kyber" => {
            let keypair: KyberKeyPair = bincode::deserialize(&key_data)
                .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize keypair: {}", e)))?;
            
            store_kyber_keypair(&keypair, key_storage_path, new_password)?
        },
        "dilithium" => {
            let keypair: DilithiumKeyPair = bincode::deserialize(&key_data)
                .map_err(|e| CryptoError::SerializationError(format!("Failed to deserialize keypair: {}", e)))?;
            
            store_dilithium_keypair(&keypair, key_storage_path, new_password)?
        },
        _ => return Err(CryptoError::key_management_error("Operation failed", &format!("Invalid key type in import file: {}", key_type), "unknown")),
    };
    
    Ok((new_key_id, key_type))
}
