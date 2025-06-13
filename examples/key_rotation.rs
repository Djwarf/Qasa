//! Example: Key Storage, Loading, and Rotation
use qasa::key_management::{store_kyber_keypair, load_kyber_keypair, rotate_kyber_keypair, RotationPolicy};
use qasa::kyber::{KyberKeyPair, KyberVariant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a Kyber key pair
    let keypair = KyberKeyPair::generate(KyberVariant::Kyber768)?;
    let password = "strong_password_123!";
    let storage_path = None; // Use default path

    // Store the key pair securely
    let key_id = store_kyber_keypair(&keypair, storage_path, password)?;
    println!("Stored Kyber key with ID: {}", key_id);

    // Load the key pair
    let loaded = load_kyber_keypair(&key_id, password, storage_path)?;
    assert_eq!(keypair.public_key, loaded.public_key);
    println!("Loaded Kyber key matches original.");

    // Rotate the key pair
    let new_key_id = rotate_kyber_keypair(&key_id, password, storage_path)?;
    println!("Rotated Kyber key. New ID: {}", new_key_id);

    // Set up a rotation policy (e.g., 30 days)
    let policy = RotationPolicy { rotation_interval_days: 30, ..Default::default() };
    println!("Rotation policy: {:?}", policy);

    Ok(())
} 