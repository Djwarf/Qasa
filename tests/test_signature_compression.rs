//! Integration tests for SPHINCS+ signature compression

use qasa::sphincsplus::{
    SphincsKeyPair,
    SphincsVariant,
    CompressionLevel,
    CompressedSignature,
    compress_signature_light,
    decompress_signature_light,
};

/// Test signature compression and decompression for all variants
#[test]
fn test_signature_compression_roundtrip() {
    // Test messages of different sizes
    let messages = [
        b"Short message".to_vec(),
        vec![b'A'; 1000], // 1KB
    ];
    
    // Test all variants
    for variant in [
        SphincsVariant::Sphincs128f,
        SphincsVariant::Sphincs128s,
        SphincsVariant::Sphincs192f,
    ] {
        // Generate a key pair
        let key_pair = SphincsKeyPair::generate(variant)
            .expect("Failed to generate key pair");
        
        for message in &messages {
            // Sign the message
            let signature = key_pair.sign(message)
                .expect("Failed to sign message");
            
            // Compress the signature using light compression
            let compressed_data = compress_signature_light(&signature)
                .expect("Failed to compress signature");
            
            // Create compressed signature object
            let compressed = CompressedSignature::new(
                compressed_data,
                CompressionLevel::Light,
                variant,
            );
            
            // Print compression stats
            println!("Variant {:?}, original size: {}, compressed size: {}", 
                variant, signature.len(), compressed.size());
            
            // Decompress the signature
            let decompressed = decompress_signature_light(compressed.data())
                .expect("Failed to decompress signature");
            
            // Verify the decompressed signature
            let is_valid = key_pair.verify(message, &decompressed)
                .expect("Failed to verify signature");
            
            assert!(is_valid, 
                "Decompressed signature should be valid for variant {:?}", 
                variant);
        }
    }
}

/// Test compression with invalid signature size
#[test]
fn test_invalid_signature_compression() {
    // Create an invalid signature (too small)
    let invalid_signature = vec![0; 100];
    
    // Try to compress it
    let result = compress_signature_light(&invalid_signature);
    
    // It should fail
    assert!(result.is_err(), "Compressing an invalid signature should fail");
}

/// Test invalid decompression
#[test]
fn test_invalid_decompression() {
    // Create an invalid compressed signature with incorrect data
    let invalid_data = vec![0xFF; 100];
    let invalid_compressed = CompressedSignature::new(
        invalid_data,
        CompressionLevel::Light,
        SphincsVariant::Sphincs128f,
    );
    
    // Try to decompress it
    let result = decompress_signature_light(invalid_compressed.data());
    
    // It should fail
    assert!(result.is_err(), "Decompressing an invalid compressed signature should fail");
}

/// Test compression performance
#[test]
fn test_compression_performance() {
    // Generate a key pair
    let key_pair = SphincsKeyPair::generate(SphincsVariant::Sphincs128f)
        .expect("Failed to generate key pair");
    
    // Sign a message
    let message = vec![b'A'; 1000]; // 1KB message
    let signature = key_pair.sign(&message)
        .expect("Failed to sign message");
    
    // Measure compression time
    let start = std::time::Instant::now();
    let compressed_data = compress_signature_light(&signature)
        .expect("Failed to compress signature");
    let compression_time = start.elapsed();
    
    let compressed = CompressedSignature::new(
        compressed_data,
        CompressionLevel::Light,
        key_pair.algorithm,
    );
    
    // Measure decompression time
    let start = std::time::Instant::now();
    let decompressed = decompress_signature_light(compressed.data())
        .expect("Failed to decompress signature");
    let decompression_time = start.elapsed();
    
    // Print performance metrics
    println!("Original size: {} bytes", signature.len());
    println!("Compressed size: {} bytes", compressed.size());
    println!("Compression ratio: {:.2}", compressed.compression_ratio());
    println!("Compression time: {:?}", compression_time);
    println!("Decompression time: {:?}", decompression_time);
    
    // Verify the decompressed signature
    let is_valid = key_pair.verify(&message, &decompressed)
        .expect("Failed to verify signature");
    assert!(is_valid, "Decompressed signature should be valid");
} 