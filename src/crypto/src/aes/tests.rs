use super::*;
use crate::utils;

#[test]
fn test_aes_encrypt_decrypt() {
    // Generate a random key
    let key = utils::random_bytes(32).unwrap();

    // Test data
    let plaintext = b"This is a test message for AES-GCM encryption";
    let aad = b"Additional authenticated data";

    // Encrypt
    let (ciphertext, nonce) = encrypt(plaintext, &key, Some(aad)).unwrap();

    // Verify ciphertext is not the same as plaintext
    assert_ne!(&ciphertext[..], &plaintext[..]);

    // Decrypt
    let decrypted = decrypt(&ciphertext, &key, &nonce, Some(aad)).unwrap();

    // Verify decryption works
    assert_eq!(&decrypted[..], &plaintext[..]);
}

#[test]
fn test_aes_tampering_detection() {
    // Generate a random key
    let key = utils::random_bytes(32).unwrap();

    // Test data
    let plaintext = b"This is a test message for tampering detection";
    let aad = b"Additional authenticated data";

    // Encrypt
    let (mut ciphertext, nonce) = encrypt(plaintext, &key, Some(aad)).unwrap();

    // Tamper with the ciphertext
    if !ciphertext.is_empty() {
        ciphertext[0] ^= 0x01; // Flip one bit
    }

    // Decrypt should fail due to tampering
    let result = decrypt(&ciphertext, &key, &nonce, Some(aad));
    assert!(result.is_err());
}

#[test]
fn test_aes_aad_validation() {
    // Generate a random key
    let key = utils::random_bytes(32).unwrap();

    // Test data
    let plaintext = b"This is a test message for AAD validation";
    let aad = b"Additional authenticated data";

    // Encrypt with original AAD
    let (ciphertext, nonce) = encrypt(plaintext, &key, Some(aad)).unwrap();

    // Try to decrypt with wrong AAD
    let wrong_aad = b"Wrong additional data";
    let result = decrypt(&ciphertext, &key, &nonce, Some(wrong_aad));
    assert!(result.is_err());

    // Decrypt with correct AAD should work
    let decrypted = decrypt(&ciphertext, &key, &nonce, Some(aad)).unwrap();
    assert_eq!(&decrypted[..], &plaintext[..]);
}
