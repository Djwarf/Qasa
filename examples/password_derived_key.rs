//! Example: Password-Based Key Derivation and Encryption
use qasa::key_management::derive_key_from_password;
use qasa::aes;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "correct horse battery staple";
    let salt = b"unique_salt_value";
    // Derive a 32-byte key using Argon2id
    let derived_key = derive_key_from_password(password, Some(salt), None)?;
    let plaintext = b"Data protected by password-derived key";

    // Encrypt
    let (ciphertext, nonce) = aes::encrypt(plaintext, &derived_key.key, None)?;
    // Decrypt
    let decrypted = aes::decrypt(&ciphertext, &derived_key.key, &nonce, None)?;
    assert_eq!(decrypted, plaintext);
    println!("Password-derived key encryption/decryption successful.");
    Ok(())
} 