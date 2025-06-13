#![no_main]

use libfuzzer_sys::fuzz_target;
use qasa::{
    init, encrypt_message, decrypt_message, sign_message, verify_message,
    encrypt_and_sign_message, decrypt_and_verify_message,
    kyber::{KyberKeyPair, KyberVariant},
    dilithium::{DilithiumKeyPair, DilithiumVariant},
};
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct HighLevelApiFuzzInput {
    message: Vec<u8>,
    kyber_variant: u8,
    dilithium_variant: u8,
    invalid_ciphertext: Vec<u8>,
    invalid_signature: Vec<u8>,
}

fuzz_target!(|input: HighLevelApiFuzzInput| {
    // Initialize the library
    let _ = init();
    
    // Map the variant inputs
    let kyber_variant = match input.kyber_variant % 3 {
        0 => KyberVariant::Kyber512,
        1 => KyberVariant::Kyber768,
        _ => KyberVariant::Kyber1024,
    };
    
    let dilithium_variant = match input.dilithium_variant % 3 {
        0 => DilithiumVariant::Dilithium2,
        1 => DilithiumVariant::Dilithium3,
        _ => DilithiumVariant::Dilithium5,
    };
    
    // Generate key pairs
    if let (Ok(kyber_keypair), Ok(dilithium_keypair)) = (
        KyberKeyPair::generate(kyber_variant),
        DilithiumKeyPair::generate(dilithium_variant)
    ) {
        let kyber_public = kyber_keypair.public_key();
        let dilithium_public = dilithium_keypair.public_key();
        
        // Test encrypt_message and decrypt_message
        if let Ok((encrypted, encapsulated, nonce)) = encrypt_message(&input.message, &kyber_public) {
            let _ = decrypt_message(&encrypted, &encapsulated, &nonce, &kyber_keypair);
            
            // Try with invalid data
            if !input.invalid_ciphertext.is_empty() {
                let _ = decrypt_message(&input.invalid_ciphertext, &encapsulated, &nonce, &kyber_keypair);
            }
        }
        
        // Test sign_message and verify_message
        if let Ok(signature) = sign_message(&input.message, &dilithium_keypair) {
            let _ = verify_message(&input.message, &signature, &dilithium_public);
            
            // Try with invalid data
            if !input.invalid_signature.is_empty() {
                let _ = verify_message(&input.message, &input.invalid_signature, &dilithium_public);
            }
        }
        
        // Test encrypt_and_sign_message and decrypt_and_verify_message
        if let Ok((encrypted, encapsulated, nonce, signature)) = encrypt_and_sign_message(
            &input.message, &kyber_public, &dilithium_keypair
        ) {
            let _ = decrypt_and_verify_message(
                &encrypted, &encapsulated, &nonce, &signature,
                &kyber_keypair, &dilithium_public
            );
            
            // Try with invalid data
            if !input.invalid_ciphertext.is_empty() && !input.invalid_signature.is_empty() {
                let _ = decrypt_and_verify_message(
                    &input.invalid_ciphertext, &encapsulated, &nonce, &signature,
                    &kyber_keypair, &dilithium_public
                );
                
                let _ = decrypt_and_verify_message(
                    &encrypted, &encapsulated, &nonce, &input.invalid_signature,
                    &kyber_keypair, &dilithium_public
                );
            }
        }
    }
});
