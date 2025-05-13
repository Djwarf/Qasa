// Integration tests for crypto module
// Tests full workflows including key generation, encryption/decryption,
// signing/verification, and key management

use std::path::Path;

use tempfile::tempdir;

use qasa_crypto::aes;
use qasa_crypto::key_management::{
    self, derive_key_from_password, store_kyber_keypair, load_kyber_keypair,
    store_dilithium_keypair, load_dilithium_keypair, rotate_kyber_keypair,
    rotate_dilithium_keypair, delete_key, export_key, import_key, get_key_age,
    check_keys_for_rotation, RotationPolicy, KeyRotationMetadata
};
use qasa_crypto::kyber::{KyberKeyPair, KyberVariant};
use qasa_crypto::dilithium::{DilithiumKeyPair, DilithiumVariant};
use qasa_crypto::error::CryptoError;
use qasa_crypto::secure_memory::{SecureBytes, with_secure_scope};

// Helper function to setup a temporary directory for key storage
fn setup_temp_dir() -> tempfile::TempDir {
    tempdir().expect("Failed to create temporary directory")
}

#[test]
fn test_kyber_encryption_workflow() {
    // 1. Generate Kyber key pair
    let alice_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Alice's Kyber key pair");
    
    let bob_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Bob's Kyber key pair");
    
    // 2. Alice extracts her public key and sends it to Bob
    let alice_public_key = alice_keypair.public_key();
    
    // 3. Bob encapsulates a shared secret using Alice's public key
    let (bob_ciphertext, bob_shared_secret) = alice_public_key.encapsulate()
        .expect("Failed to encapsulate shared secret");
    
    // 4. Bob sends ciphertext to Alice
    
    // 5. Alice decapsulates to get the same shared secret
    let alice_shared_secret = alice_keypair.decapsulate(&bob_ciphertext)
        .expect("Failed to decapsulate shared secret");
    
    // 6. Verify both parties have the same shared secret
    assert_eq!(alice_shared_secret, bob_shared_secret, 
        "Alice and Bob should have the same shared secret");
    
    // 7. Use shared secret for AES encryption
    let plaintext = b"This is a secret message from Bob to Alice";
    let (ciphertext, nonce) = aes::encrypt(plaintext, &bob_shared_secret, None)
        .expect("Failed to encrypt message");
    
    // 8. Alice decrypts the message
    let decrypted = aes::decrypt(&ciphertext, &alice_shared_secret, &nonce, None)
        .expect("Failed to decrypt message");
    
    // 9. Verify decryption was successful
    assert_eq!(decrypted, plaintext, "Decrypted message should match original plaintext");
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
    let signature = signer_keypair.sign(message)
        .expect("Failed to sign message");
    
    // 5. Verify the signature using the public key
    let is_valid = public_key.verify(message, &signature)
        .expect("Failed to verify signature");
    
    // 6. Check that signature is valid
    assert!(is_valid, "Signature should be valid");
    
    // 7. Try verification with tampered message
    let tampered_message = b"This message has been tampered with!";
    let is_invalid = public_key.verify(tampered_message, &signature)
        .expect("Failed to verify signature");
    
    // 8. Check that signature is invalid for tampered message
    assert!(!is_invalid, "Signature should be invalid for tampered message");
}

#[test]
fn test_key_storage_workflow() {
    // 1. Setup temporary directory for key storage
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();
    
    // 2. Generate Kyber and Dilithium key pairs
    let kyber_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Kyber key pair");
    
    let dilithium_keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Dilithium key pair");
    
    // 3. Store both key pairs with passwords
    let kyber_password = "secure_kyber_pw_123!";
    let dilithium_password = "secure_dilithium_pw_456!";
    
    let kyber_key_id = store_kyber_keypair(&kyber_keypair, Some(temp_path), kyber_password)
        .expect("Failed to store Kyber key pair");
    
    let dilithium_key_id = store_dilithium_keypair(&dilithium_keypair, Some(temp_path), dilithium_password)
        .expect("Failed to store Dilithium key pair");
    
    // 4. Reload both key pairs
    let loaded_kyber = load_kyber_keypair(&kyber_key_id, kyber_password)
        .expect("Failed to load Kyber key pair");
    
    let loaded_dilithium = load_dilithium_keypair(&dilithium_key_id, dilithium_password)
        .expect("Failed to load Dilithium key pair");
    
    // 5. Verify loaded keys match originals
    assert_eq!(loaded_kyber.public_key, kyber_keypair.public_key,
        "Loaded Kyber public key should match original");
    assert_eq!(loaded_kyber.secret_key, kyber_keypair.secret_key,
        "Loaded Kyber secret key should match original");
    
    assert_eq!(loaded_dilithium.public_key, dilithium_keypair.public_key,
        "Loaded Dilithium public key should match original");
    assert_eq!(loaded_dilithium.secret_key, dilithium_keypair.secret_key,
        "Loaded Dilithium secret key should match original");
    
    // 6. Try to load with incorrect password (should fail)
    let wrong_password = "wrong_password";
    let kyber_result = load_kyber_keypair(&kyber_key_id, wrong_password);
    let dilithium_result = load_dilithium_keypair(&dilithium_key_id, wrong_password);
    
    assert!(kyber_result.is_err(), "Loading Kyber key with wrong password should fail");
    assert!(dilithium_result.is_err(), "Loading Dilithium key with wrong password should fail");
}

#[test]
fn test_key_rotation_workflow() {
    // 1. Setup temporary directory for key storage
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();
    
    // 2. Generate and store initial key pairs
    let kyber_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Kyber key pair");
    
    let dilithium_keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Dilithium key pair");
    
    let password = "secure_rotation_pw_789!";
    
    let kyber_key_id = store_kyber_keypair(&kyber_keypair, Some(temp_path), password)
        .expect("Failed to store Kyber key pair");
    
    let dilithium_key_id = store_dilithium_keypair(&dilithium_keypair, Some(temp_path), password)
        .expect("Failed to store Dilithium key pair");
    
    // 3. Rotate both key pairs
    let new_kyber_key_id = rotate_kyber_keypair(&kyber_key_id, password)
        .expect("Failed to rotate Kyber key pair");
    
    let new_dilithium_key_id = rotate_dilithium_keypair(&dilithium_key_id, password)
        .expect("Failed to rotate Dilithium key pair");
    
    // 4. Verify new key IDs are different
    assert_ne!(kyber_key_id, new_kyber_key_id,
        "Rotated Kyber key ID should be different from original");
    assert_ne!(dilithium_key_id, new_dilithium_key_id,
        "Rotated Dilithium key ID should be different from original");
    
    // 5. Load both original and rotated keys
    let original_kyber = load_kyber_keypair(&kyber_key_id, password)
        .expect("Failed to load original Kyber key pair");
    
    let rotated_kyber = load_kyber_keypair(&new_kyber_key_id, password)
        .expect("Failed to load rotated Kyber key pair");
    
    let original_dilithium = load_dilithium_keypair(&dilithium_key_id, password)
        .expect("Failed to load original Dilithium key pair");
    
    let rotated_dilithium = load_dilithium_keypair(&new_dilithium_key_id, password)
        .expect("Failed to load rotated Dilithium key pair");
    
    // 6. Verify original and rotated keys are different
    assert_ne!(original_kyber.public_key, rotated_kyber.public_key,
        "Rotated Kyber public key should be different from original");
    
    assert_ne!(original_dilithium.public_key, rotated_dilithium.public_key,
        "Rotated Dilithium public key should be different from original");
    
    // 7. Verify both keys have the same algorithm variant
    assert_eq!(original_kyber.algorithm, rotated_kyber.algorithm,
        "Rotated Kyber key should have same algorithm variant as original");
    
    assert_eq!(original_dilithium.algorithm, rotated_dilithium.algorithm,
        "Rotated Dilithium key should have same algorithm variant as original");
}

#[test]
fn test_key_export_import_workflow() {
    // 1. Setup temporary directory for key storage
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();
    
    // 2. Generate and store a key pair
    let kyber_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Kyber key pair");
    
    let original_password = "original_export_pw_123!";
    
    let key_id = store_kyber_keypair(&kyber_keypair, Some(temp_path), original_password)
        .expect("Failed to store Kyber key pair");
    
    // 3. Export the key with a different password
    let export_password = "export_password_456!";
    let export_path = Path::new(temp_path).join("exported_key.bin").to_str().unwrap().to_string();
    
    export_key(&key_id, "kyber", original_password, export_password, &export_path)
        .expect("Failed to export key");
    
    // 4. Import the key with a new password
    let import_password = "import_password_789!";
    
    let (new_key_id, key_type) = import_key(&export_path, export_password, import_password)
        .expect("Failed to import key");
    
    // 5. Verify the imported key type
    assert_eq!(key_type, "kyber", "Imported key should be a Kyber key");
    
    // 6. Load the original and imported keys
    let original_key = load_kyber_keypair(&key_id, original_password)
        .expect("Failed to load original key");
    
    let imported_key = load_kyber_keypair(&new_key_id, import_password)
        .expect("Failed to load imported key");
    
    // 7. Verify the keys match
    assert_eq!(original_key.public_key, imported_key.public_key,
        "Imported key public key should match original");
    assert_eq!(original_key.secret_key, imported_key.secret_key,
        "Imported key secret key should match original");
    assert_eq!(original_key.algorithm, imported_key.algorithm,
        "Imported key algorithm should match original");
}

#[test]
fn test_full_communication_workflow() {
    // 1. Setup temporary directory for key storage
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();
    
    // 2. Generate key pairs for Alice and Bob
    let alice_kyber = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Alice's Kyber key pair");
    let alice_dilithium = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Alice's Dilithium key pair");
    
    let bob_kyber = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Bob's Kyber key pair");
    let bob_dilithium = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Bob's Dilithium key pair");
    
    // 3. Extract public keys for exchange
    let alice_kyber_public = alice_kyber.public_key();
    let alice_dilithium_public = alice_dilithium.public_key();
    
    let bob_kyber_public = bob_kyber.public_key();
    let bob_dilithium_public = bob_dilithium.public_key();
    
    // 4. Alice sends a message to Bob
    let alice_message = b"Hello Bob, this is a secure message from Alice!";
    
    // 4.1 Use Bob's public key to encapsulate a shared secret
    let (alice_to_bob_ciphertext, alice_to_bob_secret) = bob_kyber_public.encapsulate()
        .expect("Failed to encapsulate shared secret");
    
    // 4.2 Encrypt the message with the shared secret
    let (encrypted_message, nonce) = aes::encrypt(alice_message, &alice_to_bob_secret, None)
        .expect("Failed to encrypt message");
    
    // 4.3 Sign the encrypted message
    let signature = alice_dilithium.sign(&encrypted_message)
        .expect("Failed to sign encrypted message");
    
    // 5. Bob receives and processes the message
    
    // 5.1 Verify the signature using Alice's public key
    let is_authentic = bob_dilithium_public.verify(&encrypted_message, &signature)
        .expect("Failed to verify signature");
    
    assert!(is_authentic, "Signature verification should succeed");
    
    // 5.2 Decapsulate the shared secret
    let bob_shared_secret = bob_kyber.decapsulate(&alice_to_bob_ciphertext)
        .expect("Failed to decapsulate shared secret");
    
    // 5.3 Decrypt the message
    let decrypted = aes::decrypt(&encrypted_message, &bob_shared_secret, &nonce, None)
        .expect("Failed to decrypt message");
    
    // 5.4 Verify decryption was successful
    assert_eq!(decrypted, alice_message, "Decrypted message should match original message");
    
    // 6. Bob sends a response to Alice
    let bob_response = b"Hello Alice, I received your message. Thanks!";
    
    // 6.1 Use Alice's public key to encapsulate a shared secret
    let (bob_to_alice_ciphertext, bob_to_alice_secret) = alice_kyber_public.encapsulate()
        .expect("Failed to encapsulate shared secret");
    
    // 6.2 Encrypt the response
    let (encrypted_response, response_nonce) = aes::encrypt(bob_response, &bob_to_alice_secret, None)
        .expect("Failed to encrypt response");
    
    // 6.3 Sign the encrypted response
    let response_signature = bob_dilithium.sign(&encrypted_response)
        .expect("Failed to sign encrypted response");
    
    // 7. Alice receives and processes the response
    
    // 7.1 Verify the signature
    let response_authentic = alice_dilithium_public.verify(&encrypted_response, &response_signature)
        .expect("Failed to verify response signature");
    
    assert!(response_authentic, "Response signature verification should succeed");
    
    // 7.2 Decapsulate the shared secret
    let alice_response_secret = alice_kyber.decapsulate(&bob_to_alice_ciphertext)
        .expect("Failed to decapsulate response shared secret");
    
    // 7.3 Decrypt the response
    let decrypted_response = aes::decrypt(&encrypted_response, &alice_response_secret, &response_nonce, None)
        .expect("Failed to decrypt response");
    
    // 7.4 Verify response decryption was successful
    assert_eq!(decrypted_response, bob_response, "Decrypted response should match original response");
}

#[test]
fn test_secure_deletion_workflow() {
    // 1. Setup temporary directory for key storage
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();
    
    // 2. Generate and store a key pair
    let keypair = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Kyber key pair");
    
    let password = "secure_deletion_pw_123!";
    
    let key_id = store_kyber_keypair(&keypair, Some(temp_path), password)
        .expect("Failed to store Kyber key pair");
    
    // 3. Verify the key exists
    let loaded_key = load_kyber_keypair(&key_id, password);
    assert!(loaded_key.is_ok(), "Key should exist and load successfully");
    
    // 4. Delete the key
    delete_key(&key_id, "kyber").expect("Failed to delete key");
    
    // 5. Verify the key no longer exists
    let result = load_kyber_keypair(&key_id, password);
    assert!(result.is_err(), "Key should no longer exist after deletion");
    
    // 6. Verify error is the expected "file not found" type error
    match result {
        Err(CryptoError::KeyManagementError(msg)) => {
            assert!(msg.contains("Failed to open key file") || msg.contains("does not exist"), 
                "Error should indicate key file not found");
        },
        _ => panic!("Unexpected error type when loading deleted key"),
    }
}

#[test]
fn test_secure_memory_in_key_rotation() {
    // 1. Setup temporary directory for key storage
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();
    
    // 2. Generate and store a key pair with a strong password
    let kyber_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Kyber key pair");
    
    let sensitive_password = "very_sensitive_p@ssw0rd!123";
    
    // 3. Use SecureBytes to handle the password securely
    let secure_password = SecureBytes::new(sensitive_password.as_bytes());
    let password_str = std::str::from_utf8(secure_password.as_bytes()).unwrap();
    
    let key_id = store_kyber_keypair(&kyber_keypair, Some(temp_path), password_str)
        .expect("Failed to store Kyber key pair");
    
    // 4. Verify we can load the key using the secure password
    {
        let secure_password = SecureBytes::new(sensitive_password.as_bytes());
        let password_str = std::str::from_utf8(secure_password.as_bytes()).unwrap();
        
        let loaded_key = load_kyber_keypair(&key_id, password_str)
            .expect("Failed to load Kyber key pair");
        
        assert_eq!(loaded_key.public_key, kyber_keypair.public_key,
            "Loaded key should match original");
    } // secure_password is automatically zeroized here
    
    // 5. Rotate the key with secure memory handling
    let new_key_id = with_secure_scope(&mut sensitive_password.to_string(), |password| {
        rotate_kyber_keypair(&key_id, password)
    }).expect("Failed to rotate key");
    
    // 6. Verify the rotation worked
    {
        let secure_password = SecureBytes::new(sensitive_password.as_bytes());
        let password_str = std::str::from_utf8(secure_password.as_bytes()).unwrap();
        
        // Load the new key
        let new_key = load_kyber_keypair(&new_key_id, password_str)
            .expect("Failed to load rotated key");
        
        // Load the original key
        let original_key = load_kyber_keypair(&key_id, password_str)
            .expect("Failed to load original key");
        
        // Verify keys are different but have same algorithm
        assert_ne!(new_key.public_key, original_key.public_key, 
            "Rotated key should be different from original");
        assert_eq!(new_key.algorithm, original_key.algorithm,
            "Algorithm should remain the same after rotation");
    }
    
    // 7. Test key age tracking
    let key_age = get_key_age(&key_id, "kyber").expect("Failed to get key age");
    
    // Key was rotated, so it should have a days_since_rotation value
    assert!(key_age.days_since_rotation.is_some(), 
        "Original key should have a rotation timestamp");
    
    // The new key should have rotation metadata
    let new_key_age = get_key_age(&new_key_id, "kyber").expect("Failed to get new key age");
    
    // Verify the new key has the old key ID in its metadata
    assert!(!new_key_age.rotation_recommended, 
        "Newly rotated key should not need rotation");
}

#[test]
fn test_automatic_key_rotation() {
    // 1. Setup temporary directory for key storage
    let temp_dir = setup_temp_dir();
    let temp_path = temp_dir.path().to_str().unwrap();
    
    // 2. Generate and store key pairs with different policies
    let kyber_keypair1 = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate first Kyber key pair");
    
    let kyber_keypair2 = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate second Kyber key pair");
    
    let password = "rotation_test_pw_123!";
    
    // Store the first key with default policy
    let key_id1 = store_kyber_keypair(&kyber_keypair1, Some(temp_path), password)
        .expect("Failed to store first Kyber key pair");
    
    // Store the second key with high security policy (needs frequent rotation)
    let key_id2 = store_kyber_keypair(&kyber_keypair2, Some(temp_path), password)
        .expect("Failed to store second Kyber key pair");
    
    // 3. Manually set the metadata to force rotation for second key
    {
        // Load the default metadata
        let mut metadata = KeyRotationMetadata::new(RotationPolicy::high_security());
        
        // Make the key appear old by setting created_at far in the past
        use chrono::Duration;
        metadata.created_at = chrono::Utc::now() - Duration::days(60); // 60 days old
        
        // Save the modified metadata
        let _ = qasa_crypto::key_management::rotation::save_metadata(&key_id2, "kyber", &metadata);
    }
    
    // 4. Check which keys need rotation
    let keys_to_rotate = check_keys_for_rotation().expect("Failed to check keys for rotation");
    
    // Only the second key should need rotation (has high security policy and is old)
    assert!(keys_to_rotate.iter().any(|(id, key_type)| id == &key_id2 && key_type == "kyber"), 
        "Second key should need rotation");
    
    // First key should not need rotation yet (default 90-day policy)
    assert!(!keys_to_rotate.iter().any(|(id, _)| id == &key_id1), 
        "First key should not need rotation yet");
    
    // 5. Test the password provider function for auto rotation
    let rotated_keys = qasa_crypto::key_management::auto_rotate_keys(|key_id| {
        // Simple password provider that returns the same password for all keys
        Ok(password.to_string())
    }).expect("Failed to auto-rotate keys");
    
    // 6. Verify the second key was rotated
    assert!(rotated_keys.iter().any(|(old_id, _)| old_id == &key_id2), 
        "Second key should have been auto-rotated");
    
    // 7. Get the new key ID
    let new_key_id = rotated_keys.iter()
        .find(|(old_id, _)| old_id == &key_id2)
        .map(|(_, new_id)| new_id)
        .expect("Could not find new key ID");
    
    // 8. Verify both old and new keys can be loaded
    let old_key = load_kyber_keypair(&key_id2, password)
        .expect("Failed to load old key");
    
    let new_key = load_kyber_keypair(new_key_id, password)
        .expect("Failed to load new key");
    
    // Keys should be different but have same algorithm
    assert_ne!(old_key.public_key, new_key.public_key,
        "Rotated key should be different from original");
    assert_eq!(old_key.algorithm, new_key.algorithm,
        "Algorithm should remain the same after rotation");
} 