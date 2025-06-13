/*!
 * Signature Compression Example
 *
 * This example demonstrates how to use the signature compression feature
 * to reduce the size of Dilithium signatures for constrained environments.
 */

use qasa::dilithium::{
    DilithiumKeyPair,
    DilithiumVariant,
    CompressionLevel,
    compress_signature,
    decompress_signature,
};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Dilithium Signature Compression Example");
    println!("======================================\n");
    
    // Generate a Dilithium key pair
    println!("Generating Dilithium key pair...");
    let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)?;
    println!("Key pair generated successfully.");
    
    // Create a test message
    let message = b"This is a test message for signature compression";
    println!("\nMessage: {}", std::str::from_utf8(message)?);
    
    // Sign the message
    println!("\nSigning message...");
    let start = Instant::now();
    let signature = key_pair.sign(message)?;
    let signing_time = start.elapsed();
    println!("Message signed in {:?}", signing_time);
    println!("Original signature size: {} bytes", signature.len());
    
    // Verify the original signature
    println!("\nVerifying original signature...");
    let start = Instant::now();
    let is_valid = key_pair.verify(message, &signature)?;
    let verification_time = start.elapsed();
    println!("Signature verified in {:?}: {}", verification_time, is_valid);
    
    // Test different compression levels
    println!("\nCompressing signature with different levels:");
    
    for level in [
        CompressionLevel::Light,
        CompressionLevel::Medium,
        CompressionLevel::High,
    ] {
        println!("\n{:?} Compression:", level);
        
        // Compress the signature
        let start = Instant::now();
        let compressed = compress_signature(&signature, level, key_pair.algorithm)?;
        let compression_time = start.elapsed();
        
        // Calculate compression statistics
        let original_size = signature.len();
        let compressed_size = compressed.size();
        let savings = compressed.space_savings();
        let ratio = compressed.compression_ratio();
        
        println!("  Compression time: {:?}", compression_time);
        println!("  Original size: {} bytes", original_size);
        println!("  Compressed size: {} bytes", compressed_size);
        println!("  Space savings: {} bytes ({:.1}%)", 
            savings, (1.0 - ratio) * 100.0);
        
        // Decompress the signature
        let start = Instant::now();
        let decompressed = decompress_signature(&compressed)?;
        let decompression_time = start.elapsed();
        println!("  Decompression time: {:?}", decompression_time);
        
        // Verify the decompressed signature
        let start = Instant::now();
        let is_valid = key_pair.verify(message, &decompressed)?;
        let verification_time = start.elapsed();
        println!("  Verification time: {:?}", verification_time);
        println!("  Signature valid: {}", is_valid);
    }
    
    // Compare with a larger message
    println!("\nTesting with a larger message:");
    let large_message = vec![b'A'; 10000]; // 10KB message
    
    // Sign the large message
    let start = Instant::now();
    let large_signature = key_pair.sign(&large_message)?;
    let signing_time = start.elapsed();
    println!("  Large message signed in {:?}", signing_time);
    println!("  Original signature size: {} bytes", large_signature.len());
    
    // Compress with high compression
    let start = Instant::now();
    let compressed = compress_signature(&large_signature, CompressionLevel::High, key_pair.algorithm)?;
    let compression_time = start.elapsed();
    
    // Calculate compression statistics
    let original_size = large_signature.len();
    let compressed_size = compressed.size();
    let savings = compressed.space_savings();
    let ratio = compressed.compression_ratio();
    
    println!("  Compression time: {:?}", compression_time);
    println!("  Original size: {} bytes", original_size);
    println!("  Compressed size: {} bytes", compressed_size);
    println!("  Space savings: {} bytes ({:.1}%)", 
        savings, (1.0 - ratio) * 100.0);
    
    // Decompress and verify
    let decompressed = decompress_signature(&compressed)?;
    let is_valid = key_pair.verify(&large_message, &decompressed)?;
    println!("  Signature valid after compression: {}", is_valid);
    
    println!("\nExample completed successfully!");
    Ok(())
} 