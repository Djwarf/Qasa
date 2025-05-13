fn main() {
    println!("Testing OQS API with direct instantiation");
    
    // Create a new kem instance
    let alg = oqs::kem::Algorithm::Kyber768;
    let kyber = oqs::kem::Kem::new(alg).unwrap();
    
    // Generate keypair
    let (pk, sk) = kyber.keypair().unwrap();
    
    // Convert to bytes
    let pk_bytes = pk.clone().into_vec();
    let sk_bytes = sk.clone().into_vec();
    
    println!("Public key size: {} bytes", pk_bytes.len());
    println!("Secret key size: {} bytes", sk_bytes.len());

    // Try recreating the objects
    println!("\nTrying to recreate the objects from bytes...");
    
    // The correct way to recreate the objects 
    println!("Using new() method:");
    let pk_new = oqs::kem::PublicKey::new(alg, &pk_bytes).unwrap();
    let sk_new = oqs::kem::SecretKey::new(alg, &sk_bytes).unwrap();
    
    println!("New public key size: {} bytes", pk_new.len());
    println!("New secret key size: {} bytes", sk_new.len());
    
    // Test that they work correctly
    let (ct, ss1) = kyber.encapsulate(&pk_new).unwrap();
    println!("Encapsulation with recreated public key successful");
    
    let ss2 = kyber.decapsulate(&sk_new, &ct).unwrap();
    println!("Decapsulation with recreated secret key successful");
    
    println!("Shared secrets match: {}", ss1 == ss2);
    
    // Now test the signature API
    println!("\nTesting signature API");
    let alg = oqs::sig::Algorithm::Dilithium3;
    let dilithium = oqs::sig::Sig::new(alg).unwrap();
    
    // Generate keypair
    let (pk, sk) = dilithium.keypair().unwrap();
    
    // Convert to bytes
    let pk_bytes = pk.clone().into_vec();
    let sk_bytes = sk.clone().into_vec();
    
    println!("Public key size: {} bytes", pk_bytes.len());
    println!("Secret key size: {} bytes", sk_bytes.len());
    
    // Recreate the objects
    println!("\nRecreating signature objects from bytes...");
    let pk_new = oqs::sig::PublicKey::new(alg, &pk_bytes).unwrap();
    let sk_new = oqs::sig::SecretKey::new(alg, &sk_bytes).unwrap();
    
    // Test signing and verifying
    let message = b"Test message";
    let signature = dilithium.sign(message, &sk_new).unwrap();
    println!("Signature size: {} bytes", signature.len());
    
    // Recreate signature from bytes
    let sig_bytes = signature.clone().into_vec();
    let sig_new = oqs::sig::Signature::new(alg, &sig_bytes).unwrap();
    
    // Verify
    let result = dilithium.verify(message, &sig_new, &pk_new);
    println!("Verification result: {}", result.is_ok());
} 