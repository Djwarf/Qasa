/*!
 * Memory-Efficient Kyber Example for Constrained Environments
 * 
 * This example demonstrates how to use the memory-efficient Kyber implementation
 * in environments with limited memory resources, such as embedded systems or IoT devices.
 */

use qasa::kyber::{KyberVariant};
use qasa::kyber::lean::{LeanKyber, MemoryProfile, variant_for_constrained_environment};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Memory-Efficient Kyber Example for Constrained Environments");
    println!("==========================================================\n");
    
    // Simulate a constrained environment
    let available_memory_kb = 12;
    println!("Available memory: {} KB", available_memory_kb);
    
    // Determine the appropriate Kyber variant based on available memory
    let min_security_level = 3; // NIST Level 3
    println!("Minimum security level: NIST Level {}", min_security_level);
    
    let variant = match variant_for_constrained_environment(min_security_level, available_memory_kb) {
        Ok(v) => {
            println!("Selected variant: {:?}", v);
            v
        },
        Err(e) => {
            println!("Error selecting variant: {}", e);
            println!("Falling back to Kyber512");
            KyberVariant::Kyber512
        }
    };
    
    // Create a memory-efficient Kyber instance
    let mut lean_kyber = LeanKyber::new(variant, MemoryProfile::Minimal);
    println!("\nInitial memory usage: {} bytes", lean_kyber.memory_usage());
    
    // Measure key generation time
    let start = Instant::now();
    let (public_key, secret_key) = lean_kyber.generate_keypair()?;
    let keygen_time = start.elapsed();
    
    println!("\nKey Generation:");
    println!("  Time: {:?}", keygen_time);
    println!("  Public key size: {} bytes", public_key.len());
    println!("  Secret key size: {} bytes", secret_key.len());
    println!("  Memory usage: {} bytes", lean_kyber.memory_usage());
    
    // Measure encapsulation time
    let start = Instant::now();
    let (ciphertext, shared_secret) = lean_kyber.encapsulate(&public_key)?;
    let encap_time = start.elapsed();
    
    println!("\nEncapsulation:");
    println!("  Time: {:?}", encap_time);
    println!("  Ciphertext size: {} bytes", ciphertext.len());
    println!("  Shared secret size: {} bytes", shared_secret.len());
    println!("  Memory usage: {} bytes", lean_kyber.memory_usage());
    
    // Measure decapsulation time
    let start = Instant::now();
    let decapsulated_secret = lean_kyber.decapsulate(secret_key.as_bytes(), &ciphertext)?;
    let decap_time = start.elapsed();
    
    println!("\nDecapsulation:");
    println!("  Time: {:?}", decap_time);
    println!("  Memory usage: {} bytes", lean_kyber.memory_usage());
    
    // Verify that the shared secrets match
    assert_eq!(shared_secret.as_bytes(), decapsulated_secret.as_bytes(),
        "Shared secrets should match");
    println!("\nShared secrets match! ✓");
    
    // Explicitly release resources
    lean_kyber.release_resources();
    println!("\nAfter resource release:");
    println!("  Memory usage: {} bytes", lean_kyber.memory_usage());
    
    // Demonstrate one-shot functions
    println!("\nUsing one-shot functions:");
    
    // Generate key pair
    let start = Instant::now();
    let (pk, sk) = qasa::kyber::lean::generate_keypair(
        KyberVariant::Kyber512,
        MemoryProfile::Minimal,
    )?;
    println!("  Key generation time: {:?}", start.elapsed());
    
    // Encapsulate
    let start = Instant::now();
    let (ct, ss1) = qasa::kyber::lean::encapsulate(
        &pk,
        KyberVariant::Kyber512,
        MemoryProfile::Minimal,
    )?;
    println!("  Encapsulation time: {:?}", start.elapsed());
    
    // Decapsulate
    let start = Instant::now();
    let ss2 = qasa::kyber::lean::decapsulate(
        sk.as_bytes(),
        &ct,
        KyberVariant::Kyber512,
        MemoryProfile::Minimal,
    )?;
    println!("  Decapsulation time: {:?}", start.elapsed());
    
    // Verify shared secrets match
    assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "Shared secrets should match");
    println!("  Shared secrets match! ✓");
    
    // Compare memory profiles
    println!("\nMemory Profile Comparison:");
    
    for profile in [MemoryProfile::Standard, MemoryProfile::Reduced, MemoryProfile::Minimal] {
        let mut kyber = LeanKyber::new(KyberVariant::Kyber768, profile);
        let _ = kyber.generate_keypair()?;
        println!("  {:?} profile: {} bytes", profile, kyber.memory_usage());
        kyber.release_resources();
    }
    
    println!("\nExample completed successfully!");
    Ok(())
} 