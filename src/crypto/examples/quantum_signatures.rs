use qasa_crypto::{
    dilithium::{DilithiumKeyPair, DilithiumVariant},
    utils,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("QaSa Quantum-Safe Digital Signatures Demonstration");
    println!("================================================");
    println!();

    // Step 1: Generate a Dilithium key pair
    println!("Step 1: Generating a Dilithium key pair...");
    let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)?;

    println!(
        "  Security level: NIST Level {}",
        key_pair.algorithm.security_level()
    );
    println!("  Public key size: {} bytes", key_pair.public_key.len());
    println!("  Secret key size: {} bytes", key_pair.secret_key.len());

    // Extract public key (this would be shared with others)
    let public_key = key_pair.public_key();
    println!("  Public key fingerprint: {}", public_key.fingerprint());
    println!();

    // Step 2: Sign a message
    println!("Step 2: Signing a message...");
    let message = "This is an important message that needs to be authentically signed.";
    println!("  Message: \"{}\"", message);

    // Sign the message using the secret key
    let signature = key_pair.sign(message.as_bytes())?;
    println!("  Signature size: {} bytes", signature.len());
    println!("  Signature (hex): {}", utils::to_hex(&signature[0..32])); // Show only first 32 bytes
    println!();

    // Step 3: Verify the signature
    println!("Step 3: Verifying the signature...");
    let is_valid = public_key.verify(message.as_bytes(), &signature)?;
    println!(
        "  Signature verification result: {}",
        if is_valid { "VALID ✓" } else { "INVALID ✗" }
    );
    println!();

    // Step 4: Demonstrate tampered message
    println!("Step 4: Demonstrating tampered message detection...");
    let tampered_message = "This is an important message that has been tampered with!";
    println!("  Tampered message: \"{}\"", tampered_message);

    let is_valid = public_key.verify(tampered_message.as_bytes(), &signature)?;
    println!(
        "  Signature verification result: {}",
        if is_valid { "VALID ✓" } else { "INVALID ✗" }
    );
    println!("  (Expected: INVALID ✗ - message was tampered with)");
    println!();

    // Step 5: Demonstrate tampered signature
    println!("Step 5: Demonstrating tampered signature detection...");
    let mut tampered_signature = signature.clone();

    // Tamper with the signature
    if !tampered_signature.is_empty() {
        tampered_signature[0] ^= 0x01;
    }

    let is_valid = public_key.verify(message.as_bytes(), &tampered_signature)?;
    println!(
        "  Signature verification result: {}",
        if is_valid { "VALID ✓" } else { "INVALID ✗" }
    );
    println!("  (Expected: INVALID ✗ - signature was tampered with)");
    println!();

    // Step 6: Security considerations
    println!("Step 6: Security considerations");
    println!("  1. Keep the private key secure and never share it");
    println!("  2. Verify public key fingerprints through a trusted channel");
    println!("  3. Use appropriate security level for your application");
    println!("  4. Consider rotating keys periodically for long-term security");
    println!("  5. Dilithium is quantum-resistant but requires larger signatures");
    println!();

    println!("Quantum-safe digital signatures demonstration completed successfully!");

    Ok(())
}
