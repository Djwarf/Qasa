use oqs::kem::{Algorithm, Kem};

fn main() {
    let kyber = Kem::new(Algorithm::Kyber768).unwrap();
    let (pk, sk) = kyber.keypair().unwrap();

    println!("Public key size: {}", pk.len());
    println!("Secret key size: {}", sk.len());

    let pk_bytes = pk.clone().into_vec();
    println!("Public key bytes: {}", pk_bytes.len());

    // Try to use bytes to create new objects
    println!("Creating objects from bytes...");

    // Look at the methods available on pk
    println!("Methods on PublicKey:");
    println!("PublicKey::len(): {}", pk.len());
    println!("PublicKey::is_empty(): {}", pk.is_empty());
    println!("PublicKey::as_slice(): {}", pk.as_slice().len());

    // Try to create a new public key from bytes
    let pk2 = match oqs::kem::PublicKey::from_vec(pk_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Error: {:?}", e);
            return;
        }
    };

    println!("Public key 2 size: {}", pk2.len());
}
