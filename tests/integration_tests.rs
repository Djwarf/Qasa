// Integration tests for crypto module
// Tests full workflows including key generation, encryption/decryption,
// signing/verification, and key management

use tempfile::tempdir;

use qasa::aes;
use qasa::dilithium::{DilithiumKeyPair, DilithiumVariant};
use qasa::key_management::{
    delete_key, export_key, import_key, load_dilithium_keypair, load_kyber_keypair,
    rotate_dilithium_keypair, rotate_kyber_keypair, rotation, store_dilithium_keypair,
    store_kyber_keypair, KeyRotationMetadata, RotationPolicy,
};
use qasa::kyber::{KyberKeyPair, KyberVariant};
use qasa::secure_memory::with_secure_scope;

// Helper function to setup a temporary directory for key storage
fn setup_temp_dir() -> tempfile::TempDir {
    tempdir().expect("Failed to create temporary directory")
}

#[test]
fn test_kyber_encryption_workflow() {
    // 1. Generate Kyber key pair
    let mary_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Mary's Kyber key pair");

    let _elena_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Elena's Kyber key pair");

    // 2. Mary extracts her public key and sends it to Elena
    let mary_public_key = mary_keypair.public_key();

    // 3. Elena encapsulates a shared secret using Mary's public key
    let (elena_ciphertext, elena_shared_secret) = mary_public_key
        .encapsulate()
        .expect("Failed to encapsulate shared secret");

    // 4. Elena sends ciphertext to Mary

    // 5. Mary decapsulates to get the same shared secret
    let mary_shared_secret = mary_keypair
        .decapsulate(&elena_ciphertext)
        .expect("Failed to decapsulate shared secret");

    // 6. Verify both parties have the same shared secret
    assert_eq!(
        mary_shared_secret, elena_shared_secret,
        "Mary and Elena should have the same shared secret"
    );

    // 7. Use shared secret for AES encryption
    let plaintext = b"This is a secret message from Elena to Mary";
    let (ciphertext, nonce) =
        aes::encrypt(plaintext, &elena_shared_secret, None).expect("Failed to encrypt message");

    // 8. Mary decrypts the message
    let decrypted = aes::decrypt(&ciphertext, &mary_shared_secret, &nonce, None)
        .expect("Failed to decrypt message");

    // 9. Verify decryption was successful
    assert_eq!(
        decrypted, plaintext,
        "Decrypted message should match original plaintext"
    );
}

#[test]
fn test_dilithium_signature_workflow() {
    // 1. Generate Dilithium key pair
    let signer_keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate signer's Dilithium key pair");

    // 2. Extract public key to share with verifiers
    let public_key = signer_keypair.public_key();

    // 3. Create a message to sign
    let message = b"This message is authentic and has not been tampered with";

    // 4. Sign the message
    let signature = signer_keypair
        .sign(message)
        .expect("Failed to sign message");

    // 5. Verify the signature using the public key
    let is_valid = public_key
        .verify(message, &signature)
        .expect("Failed to verify signature");

    // 6. Check that signature is valid
    assert!(is_valid, "Signature should be valid");

    // 7. Try verification with tampered message
    let tampered_message = b"This message has been tampered with!";
    let is_invalid = public_key
        .verify(tampered_message, &signature)
        .expect("Failed to verify signature");

    // 8. Check that signature is invalid for tampered message
    assert!(
        !is_invalid,
        "Signature should be invalid for tampered message"
    );
}

#[test]
fn test_key_storage_workflow() {
    // 1. Setup temporary directory for key storage
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();

    // 2. Generate Kyber and Dilithium key pairs
    let kyber_keypair =
        KyberKeyPair::generate(KyberVariant::Kyber768).expect("Failed to generate Kyber key pair");

    let dilithium_keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Dilithium key pair");

    // 3. Store both key pairs with passwords
    let kyber_password = "secure_kyber_pw_123!";
    let dilithium_password = "secure_dilithium_pw_456!";

    let kyber_key_id = store_kyber_keypair(&kyber_keypair, Some(temp_path), kyber_password)
        .expect("Failed to store Kyber key pair");

    let dilithium_key_id =
        store_dilithium_keypair(&dilithium_keypair, Some(temp_path), dilithium_password)
            .expect("Failed to store Dilithium key pair");

    // 4. Reload both key pairs
    let loaded_kyber = load_kyber_keypair(&kyber_key_id, kyber_password, Some(temp_path))
        .expect("Failed to load Kyber key pair");

    let loaded_dilithium =
        load_dilithium_keypair(&dilithium_key_id, dilithium_password, Some(temp_path))
            .expect("Failed to load Dilithium key pair");

    // 5. Verify loaded keys match originals
    assert_eq!(
        loaded_kyber.public_key, kyber_keypair.public_key,
        "Loaded Kyber public key should match original"
    );
    assert_eq!(
        loaded_kyber.secret_key, kyber_keypair.secret_key,
        "Loaded Kyber secret key should match original"
    );

    assert_eq!(
        loaded_dilithium.public_key, dilithium_keypair.public_key,
        "Loaded Dilithium public key should match original"
    );
    assert_eq!(
        loaded_dilithium.secret_key, dilithium_keypair.secret_key,
        "Loaded Dilithium secret key should match original"
    );

    // 6. Try to load with incorrect password (should fail)
    let wrong_password = "wrong_password";
    let kyber_result = load_kyber_keypair(&kyber_key_id, wrong_password, Some(temp_path));
    let dilithium_result =
        load_dilithium_keypair(&dilithium_key_id, wrong_password, Some(temp_path));

    assert!(
        kyber_result.is_err(),
        "Loading Kyber key with wrong password should fail"
    );
    assert!(
        dilithium_result.is_err(),
        "Loading Dilithium key with wrong password should fail"
    );
}

#[test]
fn test_key_rotation_workflow() {
    // 1. Setup temporary directory for key storage
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();

    // 2. Generate and store initial key pairs
    let kyber_keypair =
        KyberKeyPair::generate(KyberVariant::Kyber768).expect("Failed to generate Kyber key pair");

    let dilithium_keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Dilithium key pair");

    let password = "secure_rotation_pw_789!";

    let kyber_key_id = store_kyber_keypair(&kyber_keypair, Some(temp_path), password)
        .expect("Failed to store Kyber key pair");

    let dilithium_key_id = store_dilithium_keypair(&dilithium_keypair, Some(temp_path), password)
        .expect("Failed to store Dilithium key pair");

    // 3. Rotate both key pairs
    let new_kyber_key_id = rotate_kyber_keypair(&kyber_key_id, password, Some(temp_path))
        .expect("Failed to rotate Kyber key pair");

    let new_dilithium_key_id =
        rotate_dilithium_keypair(&dilithium_key_id, password, Some(temp_path))
            .expect("Failed to rotate Dilithium key pair");

    // 4. Verify new key IDs are different
    assert_ne!(
        kyber_key_id, new_kyber_key_id,
        "Rotated Kyber key ID should be different from original"
    );
    assert_ne!(
        dilithium_key_id, new_dilithium_key_id,
        "Rotated Dilithium key ID should be different from original"
    );

    // 5. Load both original and rotated keys
    let original_kyber = load_kyber_keypair(&kyber_key_id, password, Some(temp_path))
        .expect("Failed to load original Kyber key pair");

    let rotated_kyber = load_kyber_keypair(&new_kyber_key_id, password, Some(temp_path))
        .expect("Failed to load rotated Kyber key pair");

    let original_dilithium = load_dilithium_keypair(&dilithium_key_id, password, Some(temp_path))
        .expect("Failed to load original Dilithium key pair");

    let rotated_dilithium =
        load_dilithium_keypair(&new_dilithium_key_id, password, Some(temp_path))
            .expect("Failed to load rotated Dilithium key pair");

    // 6. Verify original and rotated keys are different
    assert_ne!(
        original_kyber.public_key, rotated_kyber.public_key,
        "Rotated Kyber public key should be different from original"
    );

    assert_ne!(
        original_dilithium.public_key, rotated_dilithium.public_key,
        "Rotated Dilithium public key should be different from original"
    );

    // 7. Verify both keys have the same algorithm variant
    assert_eq!(
        original_kyber.algorithm, rotated_kyber.algorithm,
        "Rotated Kyber key should have same algorithm variant as original"
    );

    assert_eq!(
        original_dilithium.algorithm, rotated_dilithium.algorithm,
        "Rotated Dilithium key should have same algorithm variant as original"
    );
}

#[test]
fn test_key_export_import_workflow() {
    // 1. Setup temporary directory for key storage
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();

    // 2. Setup temporary directory for export
    let export_dir = setup_temp_dir();
    let export_path = export_dir.path().to_str().unwrap();

    // 3. Generate and store key pairs
    let kyber_keypair =
        KyberKeyPair::generate(KyberVariant::Kyber768).expect("Failed to generate Kyber key pair");

    let dilithium_keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Dilithium key pair");

    let storage_password = "secure_storage_pw_123!";
    let export_password = "secure_export_pw_456!";

    let kyber_key_id = store_kyber_keypair(&kyber_keypair, Some(temp_path), storage_password)
        .expect("Failed to store Kyber key pair");

    let dilithium_key_id =
        store_dilithium_keypair(&dilithium_keypair, Some(temp_path), storage_password)
            .expect("Failed to store Dilithium key pair");

    // 4. Export the keys
    let kyber_export_file = format!("{}/kyber_export.key", export_path);
    export_key(
        &kyber_key_id,
        "kyber",
        storage_password,
        export_password,
        &kyber_export_file,
        Some(temp_path),
    )
    .expect("Failed to export key");

    let dilithium_export_file = format!("{}/dilithium_export.key", export_path);
    export_key(
        &dilithium_key_id,
        "dilithium",
        storage_password,
        export_password,
        &dilithium_export_file,
        Some(temp_path),
    )
    .expect("Failed to export key");

    // 5. Import the keys to a different directory
    let import_dir = setup_temp_dir();
    let import_path = import_dir.path().to_str().unwrap();

    let import_password = "secure_import_pw_789!";

    let (imported_kyber_id, imported_kyber_type) = import_key(
        &kyber_export_file,
        export_password,
        import_password,
        Some(import_path),
    )
    .expect("Failed to import Kyber key");

    let (imported_dilithium_id, imported_dilithium_type) = import_key(
        &dilithium_export_file,
        export_password,
        import_password,
        Some(import_path),
    )
    .expect("Failed to import Dilithium key");

    // 6. Verify import worked correctly
    assert_eq!(
        imported_kyber_type, "kyber",
        "Imported Kyber key should be of type 'kyber'"
    );
    assert_eq!(
        imported_dilithium_type, "dilithium",
        "Imported Dilithium key should be of type 'dilithium'"
    );

    // 7. Load the imported keys
    let imported_kyber = load_kyber_keypair(&imported_kyber_id, import_password, Some(import_path))
        .expect("Failed to load imported Kyber key");

    let imported_dilithium =
        load_dilithium_keypair(&imported_dilithium_id, import_password, Some(import_path))
            .expect("Failed to load imported Dilithium key");

    // 8. Verify the imported keys match the originals
    assert_eq!(
        imported_kyber.public_key, kyber_keypair.public_key,
        "Imported Kyber public key should match original"
    );

    assert_eq!(
        imported_dilithium.public_key, dilithium_keypair.public_key,
        "Imported Dilithium public key should match original"
    );
}

#[test]
fn test_full_communication_workflow() {
    // 1. Setup temporary directories for Mary and Elena
    let mary_dir = setup_temp_dir();
    let mary_path = mary_dir.path().to_str().unwrap();

    let elena_dir = setup_temp_dir();
    let elena_path = elena_dir.path().to_str().unwrap();

    // 2. Generate key pairs for Mary and Elena
    let mary_kyber = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Mary's Kyber key");

    let mary_dilithium = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Mary's Dilithium key");

    let elena_kyber =
        KyberKeyPair::generate(KyberVariant::Kyber768).expect("Failed to generate Elena's Kyber key");

    let elena_dilithium = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Elena's Dilithium key");

    // 3. Store key pairs
    let mary_password = "mary_secure_pw_123!";
    let elena_password = "elena_secure_pw_456!";

    // Store Mary's keys
    let _mary_kyber_id = store_kyber_keypair(&mary_kyber, Some(mary_path), mary_password)
        .expect("Failed to store Mary's Kyber key");

    let mary_dilithium_id =
        store_dilithium_keypair(&mary_dilithium, Some(mary_path), mary_password)
            .expect("Failed to store Mary's Dilithium key");

    // Store Elena's keys
    let _elena_kyber_id = store_kyber_keypair(&elena_kyber, Some(elena_path), elena_password)
        .expect("Failed to store Elena's Kyber key");

    let _elena_dilithium_id = store_dilithium_keypair(&elena_dilithium, Some(elena_path), elena_password)
        .expect("Failed to store Elena's Dilithium key");

    // 4. Mary sends her public key to Elena
    let mary_public_key = mary_kyber.public_key();

    // 5. Elena encapsulates a shared secret using Mary's public key
    let (ciphertext, elena_shared_secret) = mary_public_key
        .encapsulate()
        .expect("Failed to encapsulate shared secret");

    // 6. Elena sends ciphertext to Mary

    // 7. Mary decapsulates to get the same shared secret
    let mary_shared_secret = mary_kyber
        .decapsulate(&ciphertext)
        .expect("Failed to decapsulate shared secret");

    // 8. Verify shared secrets match
    assert_eq!(
        mary_shared_secret, elena_shared_secret,
        "Mary and Elena should have the same shared secret"
    );

    // 9. Mary creates and signs a message for Elena
    let message = b"Hello Elena, this is a secure message from Mary!";

    // 10. Mary loads her Dilithium key for signing
    let mary_dilithium_loaded =
        load_dilithium_keypair(&mary_dilithium_id, mary_password, Some(mary_path))
            .expect("Failed to load Mary's Dilithium key");

    // 11. Mary signs the message
    let signature = mary_dilithium_loaded
        .sign(message)
        .expect("Failed to sign message");

    // 12. Mary encrypts the message using the shared secret
    let (encrypted_message, nonce) =
        aes::encrypt(message, &mary_shared_secret, None).expect("Failed to encrypt message");

    // 13. Mary sends the encrypted message, signature, and her Dilithium public key to Elena
    let mary_dilithium_public = mary_dilithium.public_key();

    // 14. Elena decrypts the message using his shared secret
    let decrypted_message = aes::decrypt(&encrypted_message, &elena_shared_secret, &nonce, None)
        .expect("Failed to decrypt message");

    // 15. Elena verifies the message signature
    let signature_valid = mary_dilithium_public
        .verify(&decrypted_message, &signature)
        .expect("Failed to verify signature");

    assert!(signature_valid, "Signature verification should succeed");
    assert_eq!(
        decrypted_message, message,
        "Decrypted message should match original"
    );
}

#[test]
fn test_secure_deletion_workflow() {
    // 1. Setup temporary directory
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();

    // 2. Generate and store keys
    let kyber_keypair =
        KyberKeyPair::generate(KyberVariant::Kyber768).expect("Failed to generate Kyber key pair");

    let password = "secure_delete_pw_123!";

    let kyber_key_id = store_kyber_keypair(&kyber_keypair, Some(temp_path), password)
        .expect("Failed to store Kyber key pair");

    // 3. Verify key can be loaded
    let loaded_key = load_kyber_keypair(&kyber_key_id, password, Some(temp_path))
        .expect("Failed to load Kyber key pair");

    assert_eq!(
        loaded_key.public_key, kyber_keypair.public_key,
        "Loaded key should match original"
    );

    // 4. Delete the key
    delete_key(&kyber_key_id, "kyber", Some(temp_path)).expect("Failed to delete key");

    // 5. Verify key can no longer be loaded
    let load_result = load_kyber_keypair(&kyber_key_id, password, Some(temp_path));
    assert!(
        load_result.is_err(),
        "Key should no longer be loadable after deletion"
    );
}

#[test]
fn test_secure_memory_in_key_rotation() {
    // 1. Setup temporary directory
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();

    // 2. Generate and store a key pair
    let kyber_keypair =
        KyberKeyPair::generate(KyberVariant::Kyber768).expect("Failed to generate Kyber key pair");

    let password = "secure_memory_test_pw_123!";

    let key_id = store_kyber_keypair(&kyber_keypair, Some(temp_path), password)
        .expect("Failed to store Kyber key pair");

    // 3. Do key rotation in a secure memory scope
    let mut new_key_id = None;

    // Create a buffer to use with secure scope
    let mut buffer: Vec<u8> = Vec::new();
    with_secure_scope(&mut buffer, |_secure_scope| {
        // Rotate key inside secure scope
        let rotated_id = rotate_kyber_keypair(&key_id, password, Some(temp_path))
            .expect("Failed to rotate Kyber key pair");

        // Store the result outside the scope
        new_key_id = Some(rotated_id);

        // Additional secure operations could happen here
    });

    // 4. Verify new key was created
    let new_key_id = new_key_id.expect("New key ID should be set");
    assert_ne!(key_id, new_key_id, "New key ID should be different");

    // 5. Load rotated key to verify it exists
    let rotated_key = load_kyber_keypair(&new_key_id, password, Some(temp_path))
        .expect("Failed to load rotated key");

    // 6. Verify key contents were updated
    assert_ne!(
        rotated_key.public_key, kyber_keypair.public_key,
        "Rotated key should have different public key"
    );
}

#[test]
fn test_automatic_key_rotation() {
    // 1. Setup temporary directory
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();

    // 2. Generate two keys with different ages
    let kyber1 =
        KyberKeyPair::generate(KyberVariant::Kyber768).expect("Failed to generate first Kyber key");

    let kyber2 = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate second Kyber key");

    let password = "auto_rotate_pw_123!";

    // 3. Store both keys
    let key1_id =
        store_kyber_keypair(&kyber1, Some(temp_path), password).expect("Failed to store first key");

    let key2_id = store_kyber_keypair(&kyber2, Some(temp_path), password)
        .expect("Failed to store second key");

    // 4. Modify key metadata to make first key old and second key very old
    let mut test_metadata1 = KeyRotationMetadata::new(RotationPolicy::default());
    test_metadata1.created_at = chrono::Utc::now() - chrono::Duration::days(80); // 80 days old

    let mut test_metadata2 = KeyRotationMetadata::new(RotationPolicy::default());
    test_metadata2.created_at = chrono::Utc::now() - chrono::Duration::days(100); // 100 days old

    // Write test metadata for both keys
    rotation::save_metadata(&key1_id, "kyber", &test_metadata1)
        .expect("Failed to save test metadata for key 1");

    rotation::save_metadata(&key2_id, "kyber", &test_metadata2)
        .expect("Failed to save test metadata for key 2");

    // 5. Run automatic key rotation with policy to rotate keys older than 90 days
    let rotated_keys = qasa::key_management::auto_rotate_keys(
        |_key_id| password.to_string(),
        Some(temp_path),
        RotationPolicy {
            rotation_interval_days: 90,
            ..Default::default()
        },
    )
    .expect("Failed to auto-rotate keys");

    // 6. Verify only the second key was rotated
    assert_eq!(rotated_keys.len(), 1, "Should have rotated one key");
    assert_eq!(
        rotated_keys[0].0, key2_id,
        "Second key should have been rotated"
    );
}
