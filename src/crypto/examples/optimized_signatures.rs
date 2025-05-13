use qasa_crypto::{
    dilithium::{
        self, DilithiumKeyPair, DilithiumVariant, LeanDilithium
    },
    error::CryptoError,
};

fn main() -> Result<(), CryptoError> {
    println!("QaSa Optimized Post-Quantum Signatures Example");
    println!("==============================================\n");
    
    // Calculate available memory for our hypothetical constrained device
    let available_memory_kb = 8; // Assuming 8KB of available memory
    let min_security_level = 2;  // Minimum required security level
    
    // Auto-select appropriate variant based on constraints
    let variant = DilithiumVariant::for_constrained_environment(min_security_level, available_memory_kb)
        .expect("No suitable variant for these constraints");
    
    println!("Selected variant: {} (requires {}KB, security level {})",
        variant, variant.memory_requirement_kb(), variant.security_level());
    
    // Message to sign
    let message = b"This is a message signed with a quantum-resistant algorithm on a constrained device";
    
    println!("\n[1] Using the LeanDilithium interface with lazy initialization");
    {
        // Create lean implementation (no resources allocated yet)
        let mut lean = LeanDilithium::new(variant);
        println!("  - Created LeanDilithium instance (lazy, no resources allocated yet)");
        
        // Generate key pair (resources are allocated on demand)
        let key_pair = lean.generate_keypair()?;
        println!("  - Generated key pair (resources allocated on demand)");
        
        // Sign message
        let signature = lean.sign(message, &key_pair.secret_key)?;
        println!("  - Signed message ({} bytes)", signature.len());
        
        // Verify signature
        let is_valid = lean.verify(message, &signature, &key_pair.public_key)?;
        println!("  - Verified signature: {}", if is_valid { "valid" } else { "invalid" });
        
        // Release resources
        lean.release_resources();
        println!("  - Released resources (memory freed)");
    }
    
    println!("\n[2] Using streamlined functions for one-off operations");
    {
        // Generate key pair with standard implementation
        let key_pair = DilithiumKeyPair::generate(variant)?;
        println!("  - Generated key pair with standard implementation");
        
        // Sign with optimized one-off function
        let signature = dilithium::lean_sign(message, &key_pair.secret_key, variant)?;
        println!("  - Signed message using lean_sign (no persistent state)");
        
        // Verify with optimized one-off function
        let is_valid = dilithium::lean_verify(message, &signature, &key_pair.public_key, variant)?;
        println!("  - Verified signature using lean_verify: {}", 
            if is_valid { "valid" } else { "invalid" });
    }
    
    println!("\n[3] Batch verification of multiple signatures");
    {
        // For this example, we'll sign the same message with different variants
        let key_pair2 = DilithiumKeyPair::generate(DilithiumVariant::Dilithium2)?;
        let key_pair3 = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)?;
        let key_pair5 = DilithiumKeyPair::generate(DilithiumVariant::Dilithium5)?;
        
        // Sign with each key pair
        let signature2 = key_pair2.sign(message)?;
        let signature3 = key_pair3.sign(message)?;
        let signature5 = key_pair5.sign(message)?;
        
        // Create a batch of signatures to verify
        let batch = vec![
            (message as &[u8], &signature2[..], &key_pair2.public_key[..], DilithiumVariant::Dilithium2),
            (message as &[u8], &signature3[..], &key_pair3.public_key[..], DilithiumVariant::Dilithium3),
            (message as &[u8], &signature5[..], &key_pair5.public_key[..], DilithiumVariant::Dilithium5),
        ];
        
        println!("  - Created batch of 3 signatures with different variants");
        
        // Verify all signatures in batch mode
        let results = dilithium::lean_verify_batch(&batch)?;
        
        // Display results
        println!("  - Batch verification results:");
        for (i, is_valid) in results.iter().enumerate() {
            println!("    Signature {}: {}", i+1, if *is_valid { "valid" } else { "invalid" });
        }
    }
    
    println!("\nAll operations completed successfully!");
    Ok(())
} 