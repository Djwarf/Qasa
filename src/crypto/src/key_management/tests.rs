use super::*;
use crate::dilithium::DilithiumVariant;
use crate::kyber::KyberVariant;
use tempfile::tempdir;

#[test]
fn test_password_derivation() {
    let password = "SecurePassword123!";
    let salt = None; // Let the function generate a salt

    let derived_key = derive_key_from_password(password, salt, None);
    assert!(derived_key.is_ok());
    
    let derived_key = derived_key.unwrap();
    assert_eq!(derived_key.key.len(), 32); // Default key length is 32 bytes
    assert!(!derived_key.salt.is_empty());
    
    // Test with custom parameters
    let params = KeyDerivationParams {
        memory_cost: 16384,
        time_cost: 2,
        parallelism: 2,
        key_length: 32,
    };
    
    let derived_key2 = derive_key_from_password(password, Some(&derived_key.salt), Some(&params));
    assert!(derived_key2.is_ok());
}

#[test]
fn test_password_verification() {
    let password = "CorrectPassword123!";
    let wrong_password = "WrongPassword123!";
    
    // Generate a derived key
    let derived_key = derive_key_from_password(password, None, None).unwrap();
    
    // Verify correct password
    let result = verify_password(password, &derived_key, None);
    assert!(result.is_ok());
    assert!(result.unwrap());
    
    // Verify incorrect password
    let result = verify_password(wrong_password, &derived_key, None);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_key_rotation_policy() {
    // Test default policy
    let default_policy = RotationPolicy::default();
    assert_eq!(default_policy.rotation_interval_days, 90);
    assert!(default_policy.keep_old_keys);
    assert_eq!(default_policy.old_keys_to_keep, 2);
    assert!(!default_policy.auto_rotate);
    
    // Test custom policy
    let rotation_interval_days = 60;
    let policy = RotationPolicy::new(rotation_interval_days);
    assert_eq!(policy.rotation_interval_days, 60);
    assert!(policy.keep_old_keys);
    
    // Test different security levels
    let high_sec = RotationPolicy::high_security();
    let std_sec = RotationPolicy::standard_security();
    let min_sec = RotationPolicy::minimal_security();
    
    assert!(high_sec.rotation_interval_days < std_sec.rotation_interval_days);
    assert!(std_sec.rotation_interval_days < min_sec.rotation_interval_days);
}

#[test]
fn test_key_rotation_metadata() {
    let policy = RotationPolicy::new(90);
    let metadata = KeyRotationMetadata::new(policy);
    
    // Test initial state
    assert!(metadata.previous_key_ids.is_empty());
    assert_eq!(metadata.last_rotated, None);
    assert_eq!(metadata.policy.rotation_interval_days, 90);
    
    // Test rotation due logic
    // (Implementation-specific tests are in rotation.rs test module)
}

#[test]
fn test_kyber_key_storage() {
    // Create a temporary directory for test keys
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();
    
    // Create a test key pair
    let key_pair = crate::kyber::KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
    let password = "TestPassword123!";

    // Test storing the key
    let store_result = store_kyber_keypair(&key_pair, Some(temp_path), password);
    assert!(store_result.is_ok());
    let key_id = store_result.unwrap();
    
    // Test loading the key
    let load_result = load_kyber_keypair(&key_id, password);
    assert!(load_result.is_ok());
    
    let loaded_key = load_result.unwrap();
    assert_eq!(loaded_key.algorithm, key_pair.algorithm);
    assert_eq!(loaded_key.public_key, key_pair.public_key);
    assert_eq!(loaded_key.secret_key, key_pair.secret_key);
    
    // Test list keys
    let list_result = list_keys();
    assert!(list_result.is_ok());
    
    // Test with wrong password
    let wrong_result = load_kyber_keypair(&key_id, "WrongPassword123!");
    assert!(wrong_result.is_err());
}

#[test]
fn test_dilithium_key_storage() {
    // Create a temporary directory for test keys
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();
    
    // Create a test key pair
    let key_pair = crate::dilithium::DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
    let password = "TestPassword123!";

    // Test storing the key
    let store_result = store_dilithium_keypair(&key_pair, Some(temp_path), password);
    assert!(store_result.is_ok());
    let key_id = store_result.unwrap();
    
    // Test loading the key
    let load_result = load_dilithium_keypair(&key_id, password);
    assert!(load_result.is_ok());
    
    let loaded_key = load_result.unwrap();
    assert_eq!(loaded_key.algorithm, key_pair.algorithm);
    assert_eq!(loaded_key.public_key, key_pair.public_key);
    assert_eq!(loaded_key.secret_key, key_pair.secret_key);
}

#[test]
fn test_key_export_import() {
    // Create temporary directories for test keys
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();
    
    let export_dir = tempdir().unwrap();
    let export_path = export_dir.path().join("exported.key").to_str().unwrap().to_string();
    
    // Create a test key pair
    let key_pair = crate::kyber::KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
    let original_password = "OriginalPassword123!";
    let export_password = "ExportPassword456!";
    let import_password = "ImportPassword789!";

    // Store the key
    let key_id = store_kyber_keypair(&key_pair, Some(temp_path), original_password).unwrap();
    
    // Export the key
    let export_result = export_key(
        &key_id, 
        "kyber", 
        original_password, 
        export_password, 
        &export_path
    );
    assert!(export_result.is_ok());
    
    // Import the key with a new password
    let import_result = import_key(
        &export_path, 
        export_password, 
        import_password
    );
    assert!(import_result.is_ok());
    
    let (new_key_id, key_type) = import_result.unwrap();
    assert_eq!(key_type, "kyber");
    
    // Load the imported key
    let load_result = load_kyber_keypair(&new_key_id, import_password);
    assert!(load_result.is_ok());
    
    // Verify the imported key matches the original
    let loaded_key = load_result.unwrap();
    assert_eq!(loaded_key.algorithm, key_pair.algorithm);
    assert_eq!(loaded_key.public_key, key_pair.public_key);
    assert_eq!(loaded_key.secret_key, key_pair.secret_key);
}

#[test]
fn test_key_rotation() {
    // Create a temporary directory for test keys
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();
    
    // Create a test key pair
    let key_pair = crate::kyber::KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
    let password = "TestPassword123!";

    // Store the key
    let key_id = store_kyber_keypair(&key_pair, Some(temp_path), password).unwrap();
    
    // Rotate the key
    let rotate_result = rotate_kyber_keypair(&key_id, password);
    assert!(rotate_result.is_ok());
    
    let new_key_id = rotate_result.unwrap();
    assert_ne!(key_id, new_key_id);
    
    // Load both keys
    let old_key = load_kyber_keypair(&key_id, password).unwrap();
    let new_key = load_kyber_keypair(&new_key_id, password).unwrap();
    
    // Keys should be different but same algorithm
    assert_eq!(old_key.algorithm, new_key.algorithm);
    assert_ne!(old_key.public_key, new_key.public_key);
    assert_ne!(old_key.secret_key, new_key.secret_key);
}
