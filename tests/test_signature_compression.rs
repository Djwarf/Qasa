//! Integration tests for Dilithium signature compression

use qasa::dilithium::{
    DilithiumKeyPair,
    DilithiumVariant,
    CompressionLevel,
    CompressedSignature,
    compress_signature,
    decompress_signature,
};

/// Test signature compression and decompression for all variants and compression levels
#[test]
fn test_signature_compression_roundtrip() {
    // Test messages of different sizes
    let messages = [
        b"Short message".to_vec(),
        vec![b'A'; 1000], // 1KB
        vec![b'B'; 10000], // 10KB
    ];
    
    // Test all variants
    for variant in [
        DilithiumVariant::Dilithium2,
        DilithiumVariant::Dilithium3,
        DilithiumVariant::Dilithium5,
    ] {
        // Generate a key pair
        let key_pair = DilithiumKeyPair::generate(variant)
            .expect("Failed to generate key pair");
        
        for message in &messages {
            // Sign the message
            let signature = key_pair.sign(message)
                .expect("Failed to sign message");
            
            // Test all compression levels
            for level in [
                CompressionLevel::Light,
                CompressionLevel::Medium,
                CompressionLevel::High,
            ] {
                // Compress the signature
                let compressed = compress_signature(&signature, level, variant)
                    .expect("Failed to compress signature");
                
                // Decompress the signature
                let decompressed = decompress_signature(&compressed)
                    .expect("Failed to decompress signature");
                
                // Verify the decompressed signature
                let is_valid = key_pair.verify(message, &decompressed)
                    .expect("Failed to verify signature");
                
                assert!(is_valid, 
                    "Decompressed signature should be valid for variant {:?} and level {:?}", 
                    variant, level);
                
                // Check that compression actually reduced the size
                assert!(compressed.size() < signature.len(),
                    "Compressed signature should be smaller than original for variant {:?} and level {:?}",
                    variant, level);
                
                // For higher compression levels, check that they achieve better compression
                if level == CompressionLevel::Medium || level == CompressionLevel::High {
                    let light_compressed = compress_signature(&signature, CompressionLevel::Light, variant)
                        .expect("Failed to compress signature with Light level");
                    
                    assert!(compressed.size() <= light_compressed.size(),
                        "Higher compression level should achieve better or equal compression");
                }
            }
        }
    }
}

/// Test compression with invalid signature size
#[test]
fn test_invalid_signature_compression() {
    // Create an invalid signature (too small)
    let invalid_signature = vec![0; 100];
    
    // Try to compress it
    let result = compress_signature(
        &invalid_signature,
        CompressionLevel::Medium,
        DilithiumVariant::Dilithium3,
    );
    
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
        CompressionLevel::Medium,
        DilithiumVariant::Dilithium3,
    );
    
    // Try to decompress it
    let result = decompress_signature(&invalid_compressed);
    
    // It should fail
    assert!(result.is_err(), "Decompressing an invalid compressed signature should fail");
}

/// Test compression space savings
#[test]
fn test_compression_space_savings() {
    // Generate a key pair
    let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate key pair");
    
    // Sign a message
    let message = b"Test message for compression space savings";
    let signature = key_pair.sign(message)
        .expect("Failed to sign message");
    
    // Compress with different levels
    let light = compress_signature(&signature, CompressionLevel::Light, key_pair.algorithm)
        .expect("Failed to compress with Light level");
    
    let medium = compress_signature(&signature, CompressionLevel::Medium, key_pair.algorithm)
        .expect("Failed to compress with Medium level");
    
    let high = compress_signature(&signature, CompressionLevel::High, key_pair.algorithm)
        .expect("Failed to compress with High level");
    
    // Check compression ratios
    println!("Original size: {} bytes", signature.len());
    println!("Light compression: {} bytes (ratio: {:.2})", 
        light.size(), light.compression_ratio());
    println!("Medium compression: {} bytes (ratio: {:.2})", 
        medium.size(), medium.compression_ratio());
    println!("High compression: {} bytes (ratio: {:.2})", 
        high.size(), high.compression_ratio());
    
    // Verify that higher compression levels achieve better compression
    assert!(light.compression_ratio() > medium.compression_ratio(),
        "Medium compression should achieve better ratio than Light");
    
    assert!(medium.compression_ratio() > high.compression_ratio(),
        "High compression should achieve better ratio than Medium");
    
    // Check minimum compression ratios
    // These are approximate targets based on the implementation
    assert!(light.compression_ratio() < 0.90, // At least 10% reduction
        "Light compression should achieve at least 10% reduction");
    
    assert!(medium.compression_ratio() < 0.80, // At least 20% reduction
        "Medium compression should achieve at least 20% reduction");
    
    assert!(high.compression_ratio() < 0.70, // At least 30% reduction
        "High compression should achieve at least 30% reduction");
}

/// Test compression and decompression performance
#[test]
fn test_compression_performance() {
    // Generate a key pair
    let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)
        .expect("Failed to generate key pair");
    
    // Sign a message
    let message = vec![b'A'; 10000]; // 10KB message
    let signature = key_pair.sign(&message)
        .expect("Failed to sign message");
    
    // Measure compression time
    let start = std::time::Instant::now();
    let compressed = compress_signature(&signature, CompressionLevel::High, key_pair.algorithm)
        .expect("Failed to compress signature");
    let compression_time = start.elapsed();
    
    // Measure decompression time
    let start = std::time::Instant::now();
    let decompressed = decompress_signature(&compressed)
        .expect("Failed to decompress signature");
    let decompression_time = start.elapsed();
    
    // Print performance metrics
    println!("Compression time: {:?}", compression_time);
    println!("Decompression time: {:?}", decompression_time);
    
    // Verify the decompressed signature
    let is_valid = key_pair.verify(&message, &decompressed)
        .expect("Failed to verify signature");
    assert!(is_valid, "Decompressed signature should be valid");
} 