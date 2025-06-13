#![no_main]

use libfuzzer_sys::fuzz_target;
use qasa::aes;
use qasa::utils;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct AesGcmFuzzInput {
    plaintext: Vec<u8>,
    key: Vec<u8>,
    nonce: Vec<u8>,
    associated_data: Option<Vec<u8>>,
    ciphertext: Vec<u8>,
    chunk_size: Option<usize>,
}

fuzz_target!(|input: AesGcmFuzzInput| {
    // Ensure we have a valid key (32 bytes for AES-256)
    let key = if input.key.len() == 32 {
        input.key.clone()
    } else {
        // Generate a random key if the input key is not the right size
        utils::random_bytes(32).unwrap_or_else(|_| vec![0; 32])
    };
    
    // Test basic encryption/decryption
    if let Ok((ciphertext, nonce)) = aes::encrypt(&input.plaintext, &key, input.associated_data.as_deref()) {
        // Try to decrypt with valid ciphertext and nonce
        let _ = aes::decrypt(&ciphertext, &key, &nonce, input.associated_data.as_deref());
    }
    
    // Try to decrypt with fuzzed ciphertext and nonce
    if input.nonce.len() == 12 {  // AES-GCM nonce size is 12 bytes
        let _ = aes::decrypt(&input.ciphertext, &key, &input.nonce, input.associated_data.as_deref());
    }
    
    // Test streaming API if available
    if let Some(chunk_size) = input.chunk_size.filter(|&size| size > 0 && size < 10_000_000) {
        // Create AesGcm instance
        if let Ok(aes_gcm) = aes::AesGcm::new(&key) {
            // Test encrypt_stream
            let mut plaintext_chunks = input.plaintext.chunks(chunk_size);
            if let Some(first_chunk) = plaintext_chunks.next() {
                if let Ok((mut encrypt_stream, nonce)) = aes_gcm.encrypt_stream(first_chunk, input.associated_data.as_deref()) {
                    // Feed remaining chunks
                    for chunk in plaintext_chunks {
                        let _ = encrypt_stream.update(chunk);
                    }
                    if let Ok(ciphertext) = encrypt_stream.finalize() {
                        // Test decrypt_stream
                        let mut ciphertext_chunks = ciphertext.chunks(chunk_size);
                        if let Some(first_chunk) = ciphertext_chunks.next() {
                            if let Ok(mut decrypt_stream) = aes_gcm.decrypt_stream(first_chunk, &nonce, input.associated_data.as_deref()) {
                                // Feed remaining chunks
                                for chunk in ciphertext_chunks {
                                    let _ = decrypt_stream.update(chunk);
                                }
                                let _ = decrypt_stream.finalize();
                            }
                        }
                    }
                }
            }
        }
    }
});
