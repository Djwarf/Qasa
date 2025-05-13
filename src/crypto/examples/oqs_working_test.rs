use oqs::kem::{self, Algorithm, Kem};

fn main() {
    println!("Testing OQS API with minimal example");

    // Create a new key pair
    let kyber = Kem::new(Algorithm::Kyber768).unwrap();
    let (pk, sk) = kyber.keypair().unwrap();

    println!("Original public key size: {}", pk.len());
    println!("Original secret key size: {}", sk.len());

    // Get bytes
    let pk_bytes = pk.into_vec();
    let sk_bytes = sk.into_vec();

    println!("Public key bytes: {} bytes", pk_bytes.len());
    println!("Secret key bytes: {} bytes", sk_bytes.len());

    // Try to use the bytes to create new OQS objects
    let kyber = Kem::new(Algorithm::Kyber768).unwrap();

    // Generate a new empty keypair to get template objects
    let (_, _) = kyber.keypair().unwrap();

    // Print available functions for the key types
    println!("Creating new objects from bytes...");

    // Try creating PublicKey from bytes
    let new_pk = match kem::PublicKey::new(Algorithm::Kyber768, &pk_bytes) {
        Ok(pk) => {
            println!("Successfully created PublicKey with new() method");
            pk
        }
        Err(e) => {
            println!("Failed to create PublicKey with new(): {:?}", e);
            // Try fallback method
            println!("Trying to create with clone_from_slice()");
            let mut raw_pk = kem::PublicKey::new_empty(Algorithm::Kyber768).unwrap();
            raw_pk.clone_from_slice(&pk_bytes);
            raw_pk
        }
    };

    println!("New public key size: {}", new_pk.len());

    // Try creating SecretKey from bytes
    let new_sk = match kem::SecretKey::new(Algorithm::Kyber768, &sk_bytes) {
        Ok(sk) => {
            println!("Successfully created SecretKey with new() method");
            sk
        }
        Err(e) => {
            println!("Failed to create SecretKey with new(): {:?}", e);
            // Try fallback method
            println!("Trying to create with clone_from_slice()");
            let mut raw_sk = kem::SecretKey::new_empty(Algorithm::Kyber768).unwrap();
            raw_sk.clone_from_slice(&sk_bytes);
            raw_sk
        }
    };

    println!("New secret key size: {}", new_sk.len());

    // Test encapsulation with the new public key
    let (ct, shared_secret1) = kyber.encapsulate(&new_pk).unwrap();
    println!("Encapsulation successful, ciphertext size: {}", ct.len());

    // Test decapsulation with the new secret key
    let shared_secret2 = kyber.decapsulate(&new_sk, &ct).unwrap();
    println!("Decapsulation successful");

    // Verify the shared secrets match
    println!("Shared secrets match: {}", shared_secret1 == shared_secret2);
}
