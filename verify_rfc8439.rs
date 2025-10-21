// Standalone RFC 8439 Test Vector Verification
// This can be compiled and run independently to verify the implementation

mod chacha20poly1305;
mod error;
mod utils;

use chacha20poly1305::{ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, encrypt, decrypt};

fn main() {
    println!("=== RFC 8439 Section 2.8.2 Test Vector Verification ===\n");

    // Test vector from RFC 8439, Section 2.8.2
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];

    let nonce = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
    ];

    let aad = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    ];

    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    // Expected outputs from RFC 8439
    let expected_ciphertext = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ];

    let expected_tag = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ];

    println!("Test inputs:");
    println!("  Key:       {:02x?}", &key[..]);
    println!("  Nonce:     {:02x?}", &nonce[..]);
    println!("  AAD:       {:02x?}", &aad[..]);
    println!("  Plaintext: {:?}\n", std::str::from_utf8(plaintext).unwrap());

    // Create key and nonce
    let chacha_key = ChaCha20Poly1305Key::new(&key).unwrap();
    let chacha_nonce = ChaCha20Poly1305Nonce::new(&nonce).unwrap();

    // Encrypt
    println!("Encrypting...");
    let result = encrypt(plaintext, Some(&aad), &chacha_key, &chacha_nonce).unwrap();

    let actual_ciphertext = &result[..plaintext.len()];
    let actual_tag = &result[plaintext.len()..];

    println!("\nCiphertext comparison:");
    println!("  Expected: {:02x?}", &expected_ciphertext[..]);
    println!("  Actual:   {:02x?}", actual_ciphertext);

    println!("\nTag comparison:");
    println!("  Expected: {:02x?}", &expected_tag[..]);
    println!("  Actual:   {:02x?}", actual_tag);

    // Verify ciphertext
    let ciphertext_match = actual_ciphertext == expected_ciphertext;
    let tag_match = actual_tag == expected_tag;

    println!("\n=== RESULTS ===");
    if ciphertext_match {
        println!("✅ Ciphertext MATCHES RFC 8439");
    } else {
        println!("❌ Ciphertext DOES NOT MATCH RFC 8439");
    }

    if tag_match {
        println!("✅ Tag MATCHES RFC 8439");
    } else {
        println!("❌ Tag DOES NOT MATCH RFC 8439");
    }

    if ciphertext_match && tag_match {
        println!("\n🎉 Implementation is RFC 8439 COMPLIANT!");

        // Test decryption
        println!("\nTesting decryption...");
        let decrypted = decrypt(&result, Some(&aad), &chacha_key, &chacha_nonce).unwrap();
        if decrypted == plaintext {
            println!("✅ Decryption successful");
        } else {
            println!("❌ Decryption failed");
        }
    } else {
        println!("\n❌ Implementation VIOLATES RFC 8439");
        std::process::exit(1);
    }
}
