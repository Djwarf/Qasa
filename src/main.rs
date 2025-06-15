use qasa::sphincsplus::*;
use qasa::error::CryptoResult;

fn main() -> CryptoResult<()> {
    println!("Testing Qasa cryptographic library...");
    
    // Test basic OQS SPHINCS+ functionality directly
    test_basic_oqs_sphincs()?;
    
    Ok(())
}

fn test_basic_oqs_sphincs() -> CryptoResult<()> {
    use oqs::sig::{Sig, Algorithm};
    
    println!("\n=== Testing OQS SPHINCS+ directly ===");
    
    let algorithm = Algorithm::SphincsShake128fSimple;
    println!("Testing algorithm: {:?}", algorithm);
    
    // Create signature instance
    let sig = Sig::new(algorithm).map_err(|e| {
        qasa::error::CryptoError::sphincs_error("OQS initialization", &e.to_string(), 9001)
    })?;
    
    println!("Sig instance created successfully");
    
    // Generate keypair
    let (pk, sk) = sig.keypair().map_err(|e| {
        qasa::error::CryptoError::sphincs_error("Key generation", &e.to_string(), 9002)
    })?;
    
    println!("Keys generated: pk={} bytes, sk={} bytes", pk.len(), sk.len());
    
    // Test message
    let message = b"Hello, SPHINCS+!";
    println!("Message: {:?}", std::str::from_utf8(message).unwrap());
    
    // Sign the message
    let signature = sig.sign(message, &sk).map_err(|e| {
        qasa::error::CryptoError::sphincs_error("Signing", &e.to_string(), 9003)
    })?;
    
    println!("Signature created: {} bytes", signature.len());
    
    // We need to work with signature bytes for display but keep the original signature for verification
    // Clone the signature as bytes just for display
    let signature_bytes = signature.clone().into_vec();
    println!("First 32 bytes of signature: {:?}", &signature_bytes[..32]);
    
    // Verify the signature using the original
    match sig.verify(message, &signature, &pk) {
        Ok(_) => println!("✓ Signature verification PASSED"),
        Err(e) => {
            println!("✗ Signature verification FAILED: {:?}", e);
            return Err(qasa::error::CryptoError::sphincs_error("Verification", &e.to_string(), 9004));
        }
    }
    
    // Test verification with wrong message
    let wrong_message = b"Wrong message";
    match sig.verify(wrong_message, &signature, &pk) {
        Ok(_) => {
            println!("✗ Verification should have failed for wrong message!");
            return Err(qasa::error::CryptoError::sphincs_error("Verification logic", "Wrong message verified as correct", 9005));
        }
        Err(_) => println!("✓ Verification correctly rejected wrong message"),
    }
    
    println!("=== OQS SPHINCS+ direct test completed successfully ===\n");
    Ok(())
} 