use oqs::kem::{self, Algorithm, Kem};
use oqs::sig::{Algorithm as SigAlgorithm, Sig};

fn main() {
    println!("Minimal OQS Test");

    // Create a new key pair for KEM
    let kyber = Kem::new(Algorithm::Kyber768).unwrap();
    let (pk, sk) = kyber.keypair().unwrap();

    println!("KEM Public key size: {}", pk.len());
    println!("KEM Secret key size: {}", sk.len());

    // Get bytes from keys
    let pk_bytes = pk.clone().into_vec();
    let sk_bytes = sk.clone().into_vec();

    println!("Public key bytes: {} bytes", pk_bytes.len());
    println!("Secret key bytes: {} bytes", sk_bytes.len());

    // Create new public key referencing the original public key
    let pk_ref = kem::PublicKeyRef::from(&pk);

    // Encapsulate with public key reference
    let (ct, ss1) = kyber.encapsulate(pk_ref).unwrap();

    // Decapsulate with original secret key
    let ss2 = kyber.decapsulate(&sk, &ct).unwrap();
    println!("KEM shared secrets match: {}", ss1 == ss2);

    // Now test signatures
    println!("\nTesting Signatures");
    let dilithium = Sig::new(SigAlgorithm::Dilithium3).unwrap();

    // Generate a key pair for signatures
    let (sig_pk, sig_sk) = dilithium.keypair().unwrap();

    println!("Signature Public key size: {}", sig_pk.len());
    println!("Signature Secret key size: {}", sig_sk.len());
    // Sign a message using the original secret key
    let message = b"This is a test message";
    let signature = dilithium.sign(message, &sig_sk).unwrap();
        println!("Signature size: {}", signature.len());

    // Verify the signature using the original public key
    let result = dilithium.verify(message, &signature, &sig_pk);
    println!("Verification result: {}", result.is_ok());
}
