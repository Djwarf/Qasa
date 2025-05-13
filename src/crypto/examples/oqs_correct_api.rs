use oqs::kem::{self, Algorithm as KemAlgorithm, Kem};
use oqs::sig::{self, Algorithm as SigAlgorithm, Sig};

fn main() {
    println!("Testing OQS API");
    
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
    
    // Recreate public key and secret key from bytes
    let pk_restored = kem::PublicKey::from_bytes(&alg, &pk_bytes).unwrap();
    let sk_restored = kem::SecretKey::from_bytes(&alg, &sk_bytes).unwrap();
    
    // Encapsulate
    let (ct, ss) = kyber.encapsulate(&pk_restored).unwrap();
    println!("Ciphertext size: {}", ct.len());
    println!("Shared secret size: {}", ss.len());
    
    // Store ciphertext
    let ct_bytes = ct.clone().into_vec();
    println!("Saved ciphertext size: {}", ct_bytes.len());
    
    // Recreate ciphertext from bytes
    let ct_restored = kem::Ciphertext::from_bytes(&alg, &ct_bytes).unwrap();
    
    // Decapsulate
    let ss2 = kyber.decapsulate(&sk_restored, &ct_restored).unwrap();
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
    
    // Recreate public key and secret key from bytes
    let pk_restored = sig::PublicKey::from_bytes(&alg, &pk_bytes).unwrap();
    let sk_restored = sig::SecretKey::from_bytes(&alg, &sk_bytes).unwrap();
    
    // Sign
    let message = b"Hello, world!";
    let signature = dilithium.sign(message, &sk_restored).unwrap();
    println!("Signature size: {}", signature.len());
    
    // Store signature
    let sig_bytes = signature.clone().into_vec();
    println!("Saved signature size: {}", sig_bytes.len());
    
    // Recreate signature from bytes
    let sig_restored = sig::Signature::from_bytes(&alg, &sig_bytes).unwrap();
    
    // Verify
    let result = dilithium.verify(message, &sig_restored, &pk_restored);
    println!("Verification result: {:?}", result.is_ok());
} 