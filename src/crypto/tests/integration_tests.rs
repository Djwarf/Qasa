// Integration tests for crypto module
// Tests full workflows including key generation, encryption/decryption,
// signing/verification, and key management

use std::path::Path;

use tempfile::tempdir;

use qasa_crypto::aes;
use qasa_crypto::key_management::{
    self, derive_key_from_password, store_kyber_keypair, load_kyber_keypair,
    store_dilithium_keypair, load_dilithium_keypair, rotate_kyber_keypair,
    rotate_dilithium_keypair, delete_key, export_key, import_key
};
use qasa_crypto::kyber::{KyberKeyPair, KyberVariant};
use qasa_crypto::dilithium::{DilithiumKeyPair, DilithiumVariant};
use qasa_crypto::error::CryptoError;

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
    let alice_public_key = alice_keypair.public_key.clone();
    
    // 3. Bob encapsulates a shared secret using Alice's public key
    let (bob_ciphertext, bob_shared_secret) = KyberKeyPair::encapsulate(&alice_public_key)
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
    let public_key = signer_keypair.public_key.clone();
    
    // 3. Create a message to sign
    let message = b"This message is authentic and has not been tampered with";
    
    // 4. Sign the message
    let signature = signer_keypair.sign(message)
        .expect("Failed to sign message");
    
    // 5. Verify the signature using the public key
    let is_valid = DilithiumKeyPair::verify(message, &signature, &public_key)
        .expect("Failed to verify signature");
    
    // 6. Check that signature is valid
    assert!(is_valid, "Signature should be valid");
    
    // 7. Try verification with tampered message
    let tampered_message = b"This message has been tampered with!";
    let is_invalid = DilithiumKeyPair::verify(tampered_message, &signature, &public_key)
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
    // Setup: Generate key pairs for Alice and Bob
    let alice_kyber = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Alice's Kyber key pair");
    
    let bob_kyber = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate Bob's Kyber key pair");
    
    let alice_dilithium = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Alice's Dilithium key pair");
    
    let bob_dilithium = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate Bob's Dilithium key pair");
    
    // 1. Exchange public keys
    let alice_kyber_public = alice_kyber.public_key.clone();
    let bob_kyber_public = bob_kyber.public_key.clone();
    
    let alice_dilithium_public = alice_dilithium.public_key.clone();
    let bob_dilithium_public = bob_dilithium.public_key.clone();
    
    // 2. Establish shared secrets
    let (ciphertext_for_alice, bob_shared_with_alice) = 
        KyberKeyPair::encapsulate(&alice_kyber_public)
        .expect("Failed to encapsulate secret for Alice");
    
    let (ciphertext_for_bob, alice_shared_with_bob) =
        KyberKeyPair::encapsulate(&bob_kyber_public)
        .expect("Failed to encapsulate secret for Bob");
    
    let alice_shared_with_bob2 = alice_kyber.decapsulate(&ciphertext_for_alice)
        .expect("Failed to decapsulate Bob's secret");
    
    let bob_shared_with_alice2 = bob_kyber.decapsulate(&ciphertext_for_bob)
        .expect("Failed to decapsulate Alice's secret");
    
    // Verify shared secrets match
    assert_eq!(alice_shared_with_bob, bob_shared_with_alice2, 
        "Alice and Bob should share the same secret");
    assert_eq!(bob_shared_with_alice, alice_shared_with_bob2,
        "Bob and Alice should share the same secret");
    
    // 3. Alice sends an encrypted and signed message to Bob
    let message = b"Hello Bob, this is Alice!";
    
    // Sign the message
    let signature = alice_dilithium.sign(message)
        .expect("Failed to sign message");
    
    // Encrypt the message using shared secret
    let (ciphertext, nonce) = aes::encrypt(message, &alice_shared_with_bob, Some(&signature))
        .expect("Failed to encrypt message");
    
    // 4. Bob receives and processes the message
    // Decrypt the message using shared secret
    let decrypted = aes::decrypt(&ciphertext, &bob_shared_with_alice2, &nonce, Some(&signature))
        .expect("Failed to decrypt message");
    
    // Verify the signature
    let is_authentic = DilithiumKeyPair::verify(&decrypted, &signature, &alice_dilithium_public)
        .expect("Failed to verify signature");
    
    // 5. Verify success
    assert_eq!(decrypted, message, "Decrypted message should match original");
    assert!(is_authentic, "Message signature should be authentic");
    
    // 6. Verify that tampering is detected
    let mut tampered_ciphertext = ciphertext.clone();
    if !tampered_ciphertext.is_empty() {
        tampered_ciphertext[0] ^= 1; // Flip a bit
    }
    
    let tamper_result = aes::decrypt(&tampered_ciphertext, &bob_shared_with_alice2, &nonce, Some(&signature));
    assert!(tamper_result.is_err(), "Decrypting tampered message should fail");
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
            assert!(msg.contains("Failed to open key file"), 
                "Error should indicate key file not found");
        },
        _ => panic!("Unexpected error type when loading deleted key"),
    }
} 