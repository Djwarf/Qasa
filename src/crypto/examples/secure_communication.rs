use qasa::{
    aes,
    kyber::{KyberKeyPair, KyberVariant},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("QaSa Quantum-Safe Cryptography Demonstration");
    println!("===========================================");
    println!();

    // Step 1: Generate Mary's and Elena's Kyber key pairs
    println!("Step 1: Generating key pairs...");
    let mary_key_pair = KyberKeyPair::generate(KyberVariant::Kyber768)?;
    let elena_key_pair = KyberKeyPair::generate(KyberVariant::Kyber768)?;

    // Extract public keys (these would be exchanged over the network)
    let mary_public_key = mary_key_pair.public_key();
    let elena_public_key = elena_key_pair.public_key();

    println!(
        "  Mary's public key fingerprint: {}",
        mary_public_key.fingerprint()
    );
    println!(
        "  Elena's public key fingerprint: {}",
        elena_public_key.fingerprint()
    );
    println!();

    // Step 2: Mary wants to send a message to Elena
    println!("Step 2: Mary prepares to send a message to Elena...");
    println!("  Mary uses Elena's public key to encapsulate a shared secret");

    // Mary uses Elena's public key to encapsulate a shared secret
    let (ciphertext, mary_shared_secret) = elena_public_key.encapsulate()?;
    println!("  Shared secret size: {} bytes", mary_shared_secret.len());
    println!("  Ciphertext size: {} bytes", ciphertext.len());
    println!();

    // Step 3: Elena receives the ciphertext and decapsulates the shared secret
    println!("Step 3: Elena receives the ciphertext and decapsulates the shared secret...");
    let elena_shared_secret = elena_key_pair.decapsulate(&ciphertext)?;

    // Verify both parties have the same shared secret
    assert_eq!(mary_shared_secret, elena_shared_secret);
    println!("  Shared secrets match! Both parties have established the same key.");
    println!();

    // Step 4: Mary encrypts a message for Elena using the shared secret
    println!("Step 4: Mary encrypts a message for Elena using the shared secret...");
    let message = "Hello Elena! This is a quantum-resistant encrypted message.";
    println!("  Original message: \"{}\"", message);

    // Use the shared secret to encrypt the message with AES-GCM
    let associated_data = b"QaSa-v1"; // Some additional authenticated data
    let (encrypted_message, nonce) = aes::encrypt(
        message.as_bytes(),
        &mary_shared_secret,
        Some(associated_data),
    )?;

    println!(
        "  Encrypted message size: {} bytes",
        encrypted_message.len()
    );
    println!("  Nonce size: {} bytes", nonce.len());
    println!("  Associated data size: {} bytes", associated_data.len());
    println!();

    // Step 5: Elena decrypts the message using the shared secret
    println!("Step 5: Elena decrypts the message using the shared secret...");
    let decrypted_bytes = aes::decrypt(
        &encrypted_message,
        &elena_shared_secret,
        &nonce,
        Some(associated_data),
    )?;

    // Convert the decrypted bytes back to a string
    let decrypted_message = std::str::from_utf8(&decrypted_bytes)?;
    println!("  Decrypted message: \"{}\"", decrypted_message);
    println!();

    // Verify the decryption was successful
    assert_eq!(message, decrypted_message);

    // Step 6: Demonstrate bidirectional communication
    println!("Step 6: Bidirectional communication (Elena replies to Mary)...");

    // Now Elena wants to reply to Mary
    // Elena uses Mary's public key to encapsulate a new shared secret
    let (reply_ciphertext, elena_to_mary_secret) = mary_public_key.encapsulate()?;

    // Mary would receive this ciphertext and decapsulate
    let mary_from_elena_secret = mary_key_pair.decapsulate(&reply_ciphertext)?;

    // Verify both parties have the same shared secret for the reply
    assert_eq!(elena_to_mary_secret, mary_from_elena_secret);

    // Elena encrypts his reply
    let reply_message = "Hi Mary! I received your quantum-resistant message safely.";
    let (encrypted_reply, reply_nonce) = aes::encrypt(
        reply_message.as_bytes(),
        &elena_to_mary_secret,
        Some(associated_data),
    )?;

    // Mary decrypts Elena's reply
    let decrypted_reply_bytes = aes::decrypt(
        &encrypted_reply,
        &mary_from_elena_secret,
        &reply_nonce,
        Some(associated_data),
    )?;

    let decrypted_reply = std::str::from_utf8(&decrypted_reply_bytes)?;
    println!("  Elena's reply: \"{}\"", decrypted_reply);
    println!();

    // Step 7: Security considerations
    println!("Step 7: Security considerations");
    println!("  1. For each new conversation, generate new Kyber key pairs");
    println!("  2. Use a unique nonce for each message");
    println!("  3. Store private keys securely");
    println!("  4. Verify public key fingerprints through a trusted channel");
    println!("  5. Use perfect forward secrecy for long conversations");
    println!();

    println!("Quantum-safe cryptography demonstration completed successfully!");

    Ok(())
}
