use oqs::kem::{self, Algorithm as KemAlgorithm, Kem};
use oqs::sig::{self, Algorithm as SigAlgorithm, Sig};

fn main() {
    println!("Testing OQS API");
    println!("OQS Version: {}", oqs::version());

    // Test KEM API
    println!("\nTesting Kyber");
    let alg = KemAlgorithm::Kyber768;
    let kyber = Kem::new(alg).unwrap();

    // Generate keypair
    let (pk, sk) = kyber.keypair().unwrap();
    println!("Public key size: {}", pk.len());
    println!("Secret key size: {}", sk.len());

    // Store public key and secret key
    let pk_bytes = pk.clone().into_vec();
    let sk_bytes = sk.clone().into_vec();
    println!("Saved public key size: {}", pk_bytes.len());
    println!("Saved secret key size: {}", sk_bytes.len());

    // Print available methods on PublicKey to find the correct API
    println!("\nPublicKey methods:");
    println!("- len()");
    println!("- is_empty()");
    println!("- as_slice()");
    println!("- into_vec()");

    // Try different approaches to create objects from bytes
    println!("\nTrying different approaches to create PublicKey from bytes:");

    println!("1. Attempting from_vec:");
    match kem::PublicKey::from_vec(pk_bytes.clone()) {
        Ok(pk2) => println!("  Success! Size: {}", pk2.len()),
        Err(e) => println!("  Error: {:?}", e),
    }

    // Test Signature API
    println!("\nTesting Dilithium");
    let alg = SigAlgorithm::Dilithium3;
    let dilithium = Sig::new(alg).unwrap();

    // Generate keypair
    let (pk, sk) = dilithium.keypair().unwrap();
    println!("Public key size: {}", pk.len());
    println!("Secret key size: {}", sk.len());

    // Store public key and secret key
    let pk_bytes = pk.clone().into_vec();
    let sk_bytes = sk.clone().into_vec();
    println!("Saved public key size: {}", pk_bytes.len());
    println!("Saved secret key size: {}", sk_bytes.len());

    // Try different approaches to create signature objects from bytes
    println!("\nTrying different approaches to create sig::PublicKey from bytes:");

    println!("1. Attempting from_vec:");
    match sig::PublicKey::from_vec(pk_bytes.clone()) {
        Ok(pk2) => println!("  Success! Size: {}", pk2.len()),
        Err(e) => println!("  Error: {:?}", e),
    }
}
