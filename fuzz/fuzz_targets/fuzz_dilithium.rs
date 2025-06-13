#![no_main]

use libfuzzer_sys::fuzz_target;
use qasa::dilithium::{DilithiumKeyPair, DilithiumPublicKey, DilithiumVariant, CompressedSignature, CompressionLevel};
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct DilithiumFuzzInput {
    variant: u8,
    message: Vec<u8>,
    signature: Vec<u8>,
    compression_level: u8,
}

fuzz_target!(|input: DilithiumFuzzInput| {
    // Map the variant input to a DilithiumVariant
    let variant = match input.variant % 3 {
        0 => DilithiumVariant::Dilithium2,
        1 => DilithiumVariant::Dilithium3,
        _ => DilithiumVariant::Dilithium5,
    };
    
    // Map compression level
    let compression_level = match input.compression_level % 3 {
        0 => CompressionLevel::Light,
        1 => CompressionLevel::Medium,
        _ => CompressionLevel::High,
    };
    
    // Try to generate a key pair
    if let Ok(key_pair) = DilithiumKeyPair::generate(variant) {
        // Test signing with valid message
        if let Ok(signature) = key_pair.sign(&input.message) {
            // Test verification with valid signature
            let _ = key_pair.verify(&input.message, &signature);
        }
        
        // Test verification with fuzzed signature
        let _ = key_pair.verify(&input.message, &input.signature);
        
        // Test public key extraction and verification
        let public_key = key_pair.public_key();
        if let Ok(signature) = key_pair.sign(&input.message) {
            let _ = public_key.verify(&input.message, &signature);
        }
        
        // Test compressed signature
        if let Ok(compressed) = key_pair.sign_compressed(&input.message, compression_level) {
            let _ = key_pair.verify_compressed(&input.message, &compressed);
            let _ = public_key.verify_compressed(&input.message, &compressed);
        }
        
        // Test serialization and deserialization
        if let Ok(serialized) = key_pair.to_bytes() {
            let _ = DilithiumKeyPair::from_bytes(&serialized);
        }
        
        if let Ok(serialized) = public_key.to_bytes() {
            let _ = DilithiumPublicKey::from_bytes(&serialized);
        }
    }
});
