use oqs::kem::{self, Algorithm as KemAlgorithm, Kem};
use oqs::sig::{self, Algorithm as SigAlgorithm, Sig};

fn main() {
    println!("Testing OQS API from_bytes method");
    println!("OQS Version: {}", oqs::version());

    // Test KEM API
    println!("\nTesting Kyber");
    let alg = KemAlgorithm::Kyber768;
    let kyber = Kem::new(alg).unwrap();

    // Generate keypair
    let (pk, sk) = kyber.keypair().unwrap();
    println!("Public key size: {}", pk.len());
    println!("Secret key size: {}", sk.len());

    // Store public key and secret key as bytes
    let pk_bytes = pk.clone().into_vec();
    let sk_bytes = sk.clone().into_vec();
    println!("Saved public key size: {}", pk_bytes.len());
    println!("Saved secret key size: {}", sk_bytes.len());

    // Print all available methods for reconstructing a public key
    println!("\nAvailable reconstruction methods:");

    // Try recreating the public key in different ways
    println!("Using TryFrom:");
    let pk_new = match kem::PublicKey::try_from(pk_bytes.clone()) {
        Ok(p) => {
            println!("  Success using TryFrom!");
            p
        }
        Err(e) => {
            println!("  Error using TryFrom: {:?}", e);
            // If TryFrom fails, use the original
            pk.clone()
        }
    };

    // Try encapsulate with the reconstructed key
    match kyber.encapsulate(&pk_new) {
        Ok((ct, ss)) => {
            println!("  Encapsulation successful with reconstructed key");
            println!("  Ciphertext size: {}", ct.len());
            println!("  Shared secret size: {}", ss.len());
        }
        Err(e) => {
            println!("  Encapsulation failed with reconstructed key: {:?}", e);
        }
    }
}
