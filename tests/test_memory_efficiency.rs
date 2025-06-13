//! Integration tests for memory-efficient implementations
//!
//! These tests verify that our memory-efficient implementations work correctly
//! and use less memory than the standard implementations.

use qasa::kyber::{self, KyberKeyPair, KyberVariant};
use qasa::kyber::lean::{LeanKyber, MemoryProfile};

/// Test the memory-efficient Kyber implementation
#[test]
fn test_lean_kyber_functionality() {
    // Create a memory-efficient Kyber instance
    let mut lean_kyber = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Minimal);
    
    // Generate a key pair
    let (public_key, secret_key) = lean_kyber.generate_keypair().expect("Failed to generate key pair");
    
    // Encapsulate a shared secret
    let (ciphertext, shared_secret1) = lean_kyber.encapsulate(&public_key).expect("Failed to encapsulate");
    
    // Decapsulate the shared secret
    let shared_secret2 = lean_kyber.decapsulate(secret_key.as_bytes(), &ciphertext)
        .expect("Failed to decapsulate");
    
    // Verify that both shared secrets match
    assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes(), 
        "Encapsulated and decapsulated shared secrets should match");
    
    // Explicitly release resources
    lean_kyber.release_resources();
}

/// Test the one-shot memory-efficient functions
#[test]
fn test_lean_kyber_oneshot_functions() {
    // Generate a key pair
    let (public_key, secret_key) = kyber::lean::generate_keypair(
        KyberVariant::Kyber512,
        MemoryProfile::Minimal,
    ).expect("Failed to generate key pair");
    
    // Encapsulate a shared secret
    let (ciphertext, shared_secret1) = kyber::lean::encapsulate(
        &public_key,
        KyberVariant::Kyber512,
        MemoryProfile::Minimal,
    ).expect("Failed to encapsulate");
    
    // Decapsulate the shared secret
    let shared_secret2 = kyber::lean::decapsulate(
        secret_key.as_bytes(),
        &ciphertext,
        KyberVariant::Kyber512,
        MemoryProfile::Minimal,
    ).expect("Failed to decapsulate");
    
    // Verify that both shared secrets match
    assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes(),
        "Encapsulated and decapsulated shared secrets should match");
}

/// Test interoperability between standard and memory-efficient implementations
#[test]
fn test_lean_kyber_interoperability() {
    // Generate a standard key pair
    let standard_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate standard key pair");
    
    // Create a memory-efficient Kyber instance
    let mut lean_kyber = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Minimal);
    
    // Encapsulate using the standard public key with the lean implementation
    let (ciphertext, lean_shared_secret) = lean_kyber.encapsulate(&standard_keypair.public_key)
        .expect("Failed to encapsulate with lean implementation");
    
    // Decapsulate using the standard implementation
    let standard_shared_secret = standard_keypair.decapsulate(&ciphertext)
        .expect("Failed to decapsulate with standard implementation");
    
    // Verify that both shared secrets match
    assert_eq!(lean_shared_secret.as_bytes(), standard_shared_secret.as_slice(),
        "Shared secrets from lean and standard implementations should match");
    
    // Now try the reverse: standard encapsulation, lean decapsulation
    let (standard_ciphertext, standard_shared_secret2) = standard_keypair.encapsulate()
        .expect("Failed to encapsulate with standard implementation");
    
    let lean_shared_secret2 = lean_kyber.decapsulate(
        &standard_keypair.secret_key,
        &standard_ciphertext
    ).expect("Failed to decapsulate with lean implementation");
    
    // Verify that both shared secrets match
    assert_eq!(lean_shared_secret2.as_bytes(), standard_shared_secret2.as_slice(),
        "Shared secrets from standard and lean implementations should match");
    
    // Cleanup
    lean_kyber.release_resources();
}

/// Test variant selection for constrained environments
#[test]
fn test_variant_selection() {
    // Test with sufficient memory for Kyber512
    let variant1 = kyber::lean::variant_for_constrained_environment(1, 10)
        .expect("Should select Kyber512");
    assert_eq!(variant1, KyberVariant::Kyber512);
    
    // Test with sufficient memory for Kyber768
    let variant2 = kyber::lean::variant_for_constrained_environment(3, 15)
        .expect("Should select Kyber768");
    assert_eq!(variant2, KyberVariant::Kyber768);
    
    // Test with sufficient memory for Kyber1024
    let variant3 = kyber::lean::variant_for_constrained_environment(5, 20)
        .expect("Should select Kyber1024");
    assert_eq!(variant3, KyberVariant::Kyber1024);
    
    // Test with insufficient memory for required security level
    let result = kyber::lean::variant_for_constrained_environment(5, 10);
    assert!(result.is_err(), "Should fail when memory is insufficient for required security level");
}

/// Compare memory usage between standard and lean implementations
#[test]
fn test_memory_usage_comparison() {
    // Create instances
    let mut lean = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Minimal);
    
    // Generate key pairs
    let (lean_pk, lean_sk) = lean.generate_keypair().expect("Failed to generate lean key pair");
    let standard_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)
        .expect("Failed to generate standard key pair");
    
    // Calculate approximate memory usage for lean implementation
    let lean_memory = lean.memory_usage();
    
    // Approximate memory usage for standard implementation
    // This is a rough estimate since we don't have a direct way to measure it
    let standard_memory = std::mem::size_of::<KyberKeyPair>() + 
        standard_keypair.public_key.len() + 
        standard_keypair.secret_key.len() +
        // Additional memory for OQS context (estimated)
        8 * 1024;
    
    println!("Memory usage comparison:");
    println!("  Lean implementation: {} bytes", lean_memory);
    println!("  Standard implementation (estimated): {} bytes", standard_memory);
    println!("  Memory savings: {} bytes ({:.1}%)", 
        standard_memory.saturating_sub(lean_memory),
        (1.0 - (lean_memory as f64 / standard_memory as f64)) * 100.0);
    
    // Verify that lean implementation uses less memory
    // Note: This is an approximate comparison and might not be exact
    assert!(lean_memory < standard_memory, 
        "Lean implementation should use less memory than standard implementation");
    
    // Cleanup
    lean.release_resources();
}

/// Test memory profiles
#[test]
fn test_memory_profiles() {
    // Create instances with different memory profiles
    let mut standard_profile = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Standard);
    let mut reduced_profile = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Reduced);
    let mut minimal_profile = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Minimal);
    
    // Generate key pairs to initialize memory
    let _ = standard_profile.generate_keypair().expect("Failed to generate key pair");
    let _ = reduced_profile.generate_keypair().expect("Failed to generate key pair");
    let _ = minimal_profile.generate_keypair().expect("Failed to generate key pair");
    
    // Get memory usage
    let standard_memory = standard_profile.memory_usage();
    let reduced_memory = reduced_profile.memory_usage();
    let minimal_memory = minimal_profile.memory_usage();
    
    println!("Memory profile comparison:");
    println!("  Standard profile: {} bytes", standard_memory);
    println!("  Reduced profile: {} bytes", reduced_memory);
    println!("  Minimal profile: {} bytes", minimal_memory);
    
    // Verify that minimal uses less than reduced, which uses less than standard
    assert!(minimal_memory <= reduced_memory, 
        "Minimal profile should use less memory than reduced profile");
    assert!(reduced_memory <= standard_memory, 
        "Reduced profile should use less memory than standard profile");
    
    // Cleanup
    standard_profile.release_resources();
    reduced_profile.release_resources();
    minimal_profile.release_resources();
} 