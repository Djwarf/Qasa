use oqs::kem::{Algorithm as KemAlgorithm, Kem};
use oqs::sig::{Algorithm as SigAlgorithm, Sig};

fn main() {
    println!("Testing OQS with the correct API");

    // Test KEM API
    println!("\nTesting Kyber");
    let alg = KemAlgorithm::Kyber768;
    let kyber = Kem::new(alg).unwrap();

    // Generate keypair
    let (pk, sk) = kyber.keypair().unwrap();
    println!("Public key size: {}", pk.len());
    println!("Secret key size: {}", sk.len());

    // Store public key and secret key bytes
    let pk_bytes = pk.clone().into_vec();
    let sk_bytes = sk.clone().into_vec();
    println!("Saved public key size: {}", pk_bytes.len());
    println!("Saved secret key size: {}", sk_bytes.len());

    // Note: We could recreate new PublicKey/SecretKey objects from the vectors,
    // but OQS doesn't provide a direct API for this. In a production system,
    // we would likely serialize/deserialize these keys.

    // Encapsulate using original public key
    let (ct, ss) = kyber.encapsulate(&pk).unwrap();
    println!("Ciphertext size: {}", ct.len());
    println!("Shared secret size: {}", ss.len());

    // Store ciphertext
    let ct_bytes = ct.clone().into_vec();
    println!("Saved ciphertext size: {}", ct_bytes.len());

    // Decapsulate using original secret key
    let ss2 = kyber.decapsulate(&sk, &ct).unwrap();
    println!("Decapsulated shared secret size: {}", ss2.len());
    println!("Shared secrets match: {}", ss == ss2);

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

    // Sign
    let message = b"Hello, world!";
    let signature = dilithium.sign(message, &sk).unwrap();
    println!("Signature size: {}", signature.len());

    // Store signature
    let sig_bytes = signature.clone().into_vec();
    println!("Saved signature size: {}", sig_bytes.len());

    // Verify
    let result = dilithium.verify(message, &signature, &pk);
    println!("Verification result: {:?}", result.is_ok());
}
