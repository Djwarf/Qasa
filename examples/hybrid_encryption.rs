//! Example: Hybrid Encryption (Kyber + AES-GCM)
use qasa::kyber::{KyberKeyPair, KyberVariant};
use qasa::aes;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate Kyber key pair for recipient
    let recipient = KyberKeyPair::generate(KyberVariant::Kyber768)?;
    let message = b"Hybrid encryption with Kyber and AES-GCM";

    // Sender encapsulates a shared secret
    let (ciphertext, shared_secret) = recipient.public_key().encapsulate()?;

    // Sender encrypts the message with the shared secret
    let (encrypted, nonce) = aes::encrypt(message, &shared_secret, None)?;

    // Recipient decapsulates the shared secret
    let decapsulated = recipient.decapsulate(&ciphertext)?;
    assert_eq!(shared_secret, decapsulated);

    // Recipient decrypts the message
    let decrypted = aes::decrypt(&encrypted, &decapsulated, &nonce, None)?;
    assert_eq!(decrypted, message);
    println!("Hybrid encryption/decryption successful.");
    Ok(())
} 