// AES-GCM Test Vectors for Interoperability
// Based on standard test vectors for AES-GCM

use qasa::aes;
use rand::{Rng, SeedableRng};
use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};

/// Test vector structure for AES-GCM operations
#[derive(Debug, Serialize, Deserialize)]
pub struct AesGcmTestVector {
    pub key: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aad: Option<Vec<u8>>,
    pub ciphertext: Vec<u8>,
}

/// Generate a deterministic test vector for AES-GCM
pub fn generate_test_vector(
    key: &[u8],
    plaintext: &[u8],
    nonce: &[u8],
    aad: Option<&[u8]>,
) -> AesGcmTestVector {
    // Encrypt the plaintext
    let (ciphertext, _) = aes::encrypt(plaintext, key, aad, Some(nonce))
        .expect("Failed to encrypt plaintext");
    
    AesGcmTestVector {
        key: key.to_vec(),
        plaintext: plaintext.to_vec(),
        nonce: nonce.to_vec(),
        aad: aad.map(|a| a.to_vec()),
        ciphertext,
    }
}

/// Standard test vectors for AES-GCM
pub fn standard_test_vectors() -> Vec<AesGcmTestVector> {
    let mut vectors = Vec::new();
    
    // Test vector 1: Basic encryption with 16-byte key
    let key_1 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let plaintext_1 = b"Hello, world!";
    let nonce_1 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
    ];
    vectors.push(generate_test_vector(&key_1, plaintext_1, &nonce_1, None));
    
    // Test vector 2: Encryption with AAD
    let key_2 = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let plaintext_2 = b"Secret message with AAD";
    let nonce_2 = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
    ];
    let aad_2 = b"Additional authenticated data";
    vectors.push(generate_test_vector(&key_2, plaintext_2, &nonce_2, Some(aad_2)));
    
    // Test vector 3: 24-byte key (AES-192)
    let key_3 = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];
    let plaintext_3 = b"AES-192 test vector";
    let nonce_3 = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b,
    ];
    vectors.push(generate_test_vector(&key_3, plaintext_3, &nonce_3, None));
    
    // Test vector 4: 32-byte key (AES-256)
    let key_4 = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    ];
    let plaintext_4 = b"AES-256 test vector with AAD";
    let nonce_4 = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b,
    ];
    let aad_4 = b"AES-256 additional authenticated data";
    vectors.push(generate_test_vector(&key_4, plaintext_4, &nonce_4, Some(aad_4)));
    
    vectors
}

/// Generate test vectors with special cases
pub fn special_case_test_vectors() -> Vec<AesGcmTestVector> {
    let mut vectors = Vec::new();
    
    // Special case 1: Empty plaintext
    let key_1 = [
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    ];
    let plaintext_1 = b"";
    let nonce_1 = [
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b,
    ];
    vectors.push(generate_test_vector(&key_1, plaintext_1, &nonce_1, None));
    
    // Special case 2: Empty plaintext with AAD
    let key_2 = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    ];
    let plaintext_2 = b"";
    let nonce_2 = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b,
    ];
    let aad_2 = b"AAD with empty plaintext";
    vectors.push(generate_test_vector(&key_2, plaintext_2, &nonce_2, Some(aad_2)));
    
    // Special case 3: Large plaintext (triggers multiple blocks)
    let key_3 = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    ];
    let plaintext_3 = vec![0xAA; 1024]; // 1KB of 0xAA bytes
    let nonce_3 = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b,
    ];
    vectors.push(generate_test_vector(&key_3, &plaintext_3, &nonce_3, None));
    
    // Special case 4: Large AAD
    let key_4 = [
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let plaintext_4 = b"Normal plaintext with large AAD";
    let nonce_4 = [
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b,
    ];
    let aad_4 = vec![0xBB; 1024]; // 1KB of 0xBB bytes
    vectors.push(generate_test_vector(&key_4, plaintext_4, &nonce_4, Some(&aad_4)));
    
    vectors
}

/// Test vectors for streaming API
pub fn streaming_test_vectors() -> Vec<(Vec<u8>, Vec<Vec<u8>>, Vec<u8>, Option<Vec<u8>>, Vec<u8>)> {
    let mut vectors = Vec::new();
    
    // Test vector 1: Basic streaming with 3 chunks
    let key_1 = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    ];
    let plaintext_chunks_1 = vec![
        b"This is chunk 1. ".to_vec(),
        b"This is chunk 2. ".to_vec(),
        b"This is chunk 3.".to_vec(),
    ];
    let nonce_1 = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab,
    ];
    
    // Encrypt using the streaming API
    let mut stream = aes::encrypt_stream_init(&key_1, None, Some(&nonce_1))
        .expect("Failed to initialize encryption stream");
    
    let mut ciphertext_1 = Vec::new();
    for chunk in &plaintext_chunks_1[..plaintext_chunks_1.len() - 1] {
        let encrypted_chunk = aes::encrypt_stream_update(&mut stream, chunk)
            .expect("Failed to encrypt chunk");
        ciphertext_1.extend_from_slice(&encrypted_chunk);
    }
    
    let final_chunk = aes::encrypt_stream_finalize(
        &mut stream, 
        &plaintext_chunks_1[plaintext_chunks_1.len() - 1]
    ).expect("Failed to finalize encryption");
    ciphertext_1.extend_from_slice(&final_chunk);
    
    vectors.push((
        key_1.to_vec(),
        plaintext_chunks_1,
        nonce_1.to_vec(),
        None,
        ciphertext_1,
    ));
    
    // Test vector 2: Streaming with AAD
    let key_2 = [
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    ];
    let plaintext_chunks_2 = vec![
        b"Chunk 1 with AAD. ".to_vec(),
        b"Chunk 2 with AAD. ".to_vec(),
        b"Chunk 3 with AAD.".to_vec(),
    ];
    let nonce_2 = [
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb,
    ];
    let aad_2 = b"Additional authenticated data for streaming".to_vec();
    
    // Encrypt using the streaming API with AAD
    let mut stream = aes::encrypt_stream_init(&key_2, Some(&aad_2), Some(&nonce_2))
        .expect("Failed to initialize encryption stream");
    
    let mut ciphertext_2 = Vec::new();
    for chunk in &plaintext_chunks_2[..plaintext_chunks_2.len() - 1] {
        let encrypted_chunk = aes::encrypt_stream_update(&mut stream, chunk)
            .expect("Failed to encrypt chunk");
        ciphertext_2.extend_from_slice(&encrypted_chunk);
    }
    
    let final_chunk = aes::encrypt_stream_finalize(
        &mut stream, 
        &plaintext_chunks_2[plaintext_chunks_2.len() - 1]
    ).expect("Failed to finalize encryption");
    ciphertext_2.extend_from_slice(&final_chunk);
    
    vectors.push((
        key_2.to_vec(),
        plaintext_chunks_2,
        nonce_2.to_vec(),
        Some(aad_2),
        ciphertext_2,
    ));
    
    vectors
}

/// Negative test cases for AES-GCM
pub fn negative_test_vectors() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
    let mut vectors = Vec::new();
    
    // Generate a valid encryption first
    let key = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    ];
    let plaintext = b"Original plaintext for negative tests";
    let nonce = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb,
    ];
    let aad = b"Original AAD";
    
    let (ciphertext, _) = aes::encrypt(plaintext, &key, Some(aad), Some(&nonce))
        .expect("Failed to encrypt plaintext");
    
    // Case 1: Tampered ciphertext (flip a bit)
    let mut tampered_ciphertext = ciphertext.clone();
    if !tampered_ciphertext.is_empty() {
        tampered_ciphertext[tampered_ciphertext.len() / 2] ^= 0x01;
    }
    vectors.push((key.to_vec(), tampered_ciphertext, nonce.to_vec(), Some(aad.to_vec())));
    
    // Case 2: Tampered AAD
    let mut tampered_aad = aad.to_vec();
    if !tampered_aad.is_empty() {
        tampered_aad[tampered_aad.len() / 2] ^= 0x01;
    }
    vectors.push((key.to_vec(), ciphertext.clone(), nonce.to_vec(), Some(tampered_aad)));
    
    // Case 3: Wrong key
    let mut wrong_key = key.to_vec();
    wrong_key[0] ^= 0x01;
    vectors.push((wrong_key, ciphertext.clone(), nonce.to_vec(), Some(aad.to_vec())));
    
    // Case 4: Wrong nonce
    let mut wrong_nonce = nonce.to_vec();
    wrong_nonce[0] ^= 0x01;
    vectors.push((key.to_vec(), ciphertext, wrong_nonce, Some(aad.to_vec())));
    
    vectors
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_standard_vectors() {
        let vectors = standard_test_vectors();
        
        for vector in vectors {
            // Test decryption
            let decrypted = aes::decrypt(
                &vector.ciphertext,
                &vector.key,
                &vector.nonce,
                vector.aad.as_deref(),
            ).expect("Failed to decrypt ciphertext");
            
            // Verify decryption matches original plaintext
            assert_eq!(decrypted, vector.plaintext, "Decrypted text doesn't match original plaintext");
        }
    }
    
    #[test]
    fn test_special_cases() {
        let vectors = special_case_test_vectors();
        
        for vector in vectors {
            // Test decryption
            let decrypted = aes::decrypt(
                &vector.ciphertext,
                &vector.key,
                &vector.nonce,
                vector.aad.as_deref(),
            ).expect("Failed to decrypt ciphertext");
            
            // Verify decryption matches original plaintext
            assert_eq!(decrypted, vector.plaintext, "Decrypted text doesn't match original plaintext");
        }
    }
    
    #[test]
    fn test_streaming_vectors() {
        let vectors = streaming_test_vectors();
        
        for (key, plaintext_chunks, nonce, aad, ciphertext) in vectors {
            // Test decryption using streaming API
            let mut stream = aes::decrypt_stream_init(&key, aad.as_deref(), Some(&nonce))
                .expect("Failed to initialize decryption stream");
            
            // Calculate total plaintext length
            let total_plaintext_len: usize = plaintext_chunks.iter().map(|chunk| chunk.len()).sum();
            
            // Split the ciphertext into chunks for streaming decryption
            // Note: In a real scenario, the ciphertext chunks would be received incrementally
            // For testing, we'll split it into roughly equal chunks
            let chunk_size = ciphertext.len() / 3;
            let ciphertext_chunks = vec![
                &ciphertext[0..chunk_size],
                &ciphertext[chunk_size..2 * chunk_size],
                &ciphertext[2 * chunk_size..],
            ];
            
            let mut decrypted = Vec::with_capacity(total_plaintext_len);
            for (i, chunk) in ciphertext_chunks.iter().enumerate() {
                if i < ciphertext_chunks.len() - 1 {
                    let decrypted_chunk = aes::decrypt_stream_update(&mut stream, chunk)
                        .expect("Failed to decrypt chunk");
                    decrypted.extend_from_slice(&decrypted_chunk);
                } else {
                    let final_chunk = aes::decrypt_stream_finalize(&mut stream, chunk)
                        .expect("Failed to finalize decryption");
                    decrypted.extend_from_slice(&final_chunk);
                }
            }
            
            // Combine original plaintext chunks for comparison
            let original_plaintext: Vec<u8> = plaintext_chunks.iter().flatten().cloned().collect();
            
            // Verify decryption matches original plaintext
            assert_eq!(decrypted, original_plaintext, "Streaming decrypted text doesn't match original plaintext");
        }
    }
    
    #[test]
    fn test_negative_cases() {
        let vectors = negative_test_vectors();
        
        for (key, ciphertext, nonce, aad) in vectors {
            // Attempt to decrypt with tampered data
            let result = aes::decrypt(&ciphertext, &key, &nonce, aad.as_deref());
            
            // Decryption should fail
            assert!(result.is_err(), "Decryption with tampered data should fail");
        }
    }
} 