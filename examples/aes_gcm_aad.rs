//! Example: AES-GCM with Associated Data (AAD)
use qasa::aes;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = b"an_example_very_secure_key_32bytes!";
    let plaintext = b"Sensitive data with context";
    let aad = b"contextual-metadata";

    // Encrypt with AAD
    let (ciphertext, nonce) = aes::encrypt(plaintext, key, Some(aad))?;
    println!("Ciphertext: {:x?}", ciphertext);
    println!("Nonce: {:x?}", nonce);

    // Decrypt with AAD
    let decrypted = aes::decrypt(&ciphertext, key, &nonce, Some(aad))?;
    assert_eq!(decrypted, plaintext);
    println!("Decryption successful and AAD verified.");
    Ok(())
} 