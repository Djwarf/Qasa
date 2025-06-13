#![no_main]

use libfuzzer_sys::fuzz_target;
use qasa::kyber::{KyberKeyPair, KyberPublicKey, KyberVariant};
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct KyberFuzzInput {
    variant: u8,
    ciphertext: Vec<u8>,
}

fuzz_target!(|input: KyberFuzzInput| {
    // Map the variant input to a KyberVariant
    let variant = match input.variant % 3 {
        0 => KyberVariant::Kyber512,
        1 => KyberVariant::Kyber768,
        _ => KyberVariant::Kyber1024,
    };
    
    // Try to generate a key pair
    if let Ok(key_pair) = KyberKeyPair::generate(variant) {
        // Test encapsulation
        if let Ok((ciphertext, shared_secret)) = key_pair.encapsulate() {
            // Test decapsulation with valid ciphertext
            let _ = key_pair.decapsulate(&ciphertext);
        }
        
        // Test decapsulation with fuzzed ciphertext
        let _ = key_pair.decapsulate(&input.ciphertext);
        
        // Test public key extraction and encapsulation
        let public_key = key_pair.public_key();
        let _ = public_key.encapsulate();
        
        // Test serialization and deserialization
        if let Ok(serialized) = key_pair.to_bytes() {
            let _ = KyberKeyPair::from_bytes(&serialized);
        }
        
        if let Ok(serialized) = public_key.to_bytes() {
            let _ = KyberPublicKey::from_bytes(&serialized);
        }
    }
});
