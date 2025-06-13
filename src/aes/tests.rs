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
fn test_aes_without_aad() {
    // Generate a random key
    let key = utils::random_bytes(32).unwrap();

    // Test data
    let plaintext = b"This is a test message without AAD";

    // Encrypt without AAD
    let (ciphertext, nonce) = encrypt(plaintext, &key, None).unwrap();

    // Decrypt without AAD
    let decrypted = decrypt(&ciphertext, &key, &nonce, None).unwrap();

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

    // Encrypt with AAD
    let (ciphertext, nonce) = encrypt(plaintext, &key, Some(aad)).unwrap();

    // Decrypt with same AAD should work
    let decrypted = decrypt(&ciphertext, &key, &nonce, Some(aad)).unwrap();
    assert_eq!(&decrypted[..], &plaintext[..]);

    // Decrypt with different AAD should fail because AAD is authenticated
    let different_aad = b"Different authenticated data";
    let result = decrypt(&ciphertext, &key, &nonce, Some(different_aad));
    assert!(result.is_err(), "Decryption should fail with different AAD");

    // Decrypt with no AAD should also fail when AAD was used for encryption
    let result = decrypt(&ciphertext, &key, &nonce, None);
    assert!(result.is_err(), "Decryption should fail with missing AAD");
}

#[test]
fn test_aes_reuse_cipher() {
    // Generate a random key
    let key = utils::random_bytes(32).unwrap();

    // Create a cipher instance
    let cipher = AesGcm::new(&key).unwrap();

    // Test data
    let plaintext1 = b"First message to encrypt";
    let plaintext2 = b"Second message to encrypt";

    // Generate nonces
    let nonce1 = AesGcm::generate_nonce();
    let nonce2 = AesGcm::generate_nonce();

    // Encrypt both messages
    let ciphertext1 = cipher.encrypt(plaintext1, &nonce1, None).unwrap();
    let ciphertext2 = cipher.encrypt(plaintext2, &nonce2, None).unwrap();

    // Decrypt both messages
    let decrypted1 = cipher.decrypt(&ciphertext1, &nonce1, None).unwrap();
    let decrypted2 = cipher.decrypt(&ciphertext2, &nonce2, None).unwrap();

    // Verify both decryptions work
    assert_eq!(&decrypted1[..], &plaintext1[..]);
    assert_eq!(&decrypted2[..], &plaintext2[..]);
}

#[test]
fn test_aes_clone_cipher() {
    // Generate a random key
    let key = utils::random_bytes(32).unwrap();

    // Create a cipher instance
    let cipher1 = AesGcm::new(&key).unwrap();

    // Clone the cipher
    let cipher2 = cipher1.clone();

    // Test data
    let plaintext = b"Message to encrypt and decrypt with cloned cipher";
    let nonce = AesGcm::generate_nonce();

    // Encrypt with first cipher
    let ciphertext = cipher1.encrypt(plaintext, &nonce, None).unwrap();

    // Decrypt with cloned cipher
    let decrypted = cipher2.decrypt(&ciphertext, &nonce, None).unwrap();

    // Verify decryption works
    assert_eq!(&decrypted[..], &plaintext[..]);
}

#[test]
fn test_aes_aad_empty_vs_none() {
    // Test behavior with empty AAD vs no AAD
    let key = utils::random_bytes(32).unwrap();
    let plaintext = b"Testing empty AAD vs no AAD";

    // Encrypt with empty AAD
    let empty_aad = b"";
    let (ciphertext1, nonce1) = encrypt(plaintext, &key, Some(empty_aad)).unwrap();

    // Encrypt with no AAD
    let (ciphertext2, nonce2) = encrypt(plaintext, &key, None).unwrap();

    // In AES-GCM, an empty AAD is cryptographically different from no AAD
    // But in our implementation using the aes-gcm crate's API, they're treated the same

    // Both should decrypt with their respective AAD settings
    let decrypted1 = decrypt(&ciphertext1, &key, &nonce1, Some(empty_aad)).unwrap();
    let decrypted2 = decrypt(&ciphertext2, &key, &nonce2, None).unwrap();

    assert_eq!(&decrypted1[..], plaintext);
    assert_eq!(&decrypted2[..], plaintext);

    // Since our implementation treats empty AAD and None the same way,
    // cross-decryption should work too (different from strict AEAD behavior)
    let decrypted_cross1 = decrypt(&ciphertext1, &key, &nonce1, None).unwrap();
    let decrypted_cross2 = decrypt(&ciphertext2, &key, &nonce2, Some(empty_aad)).unwrap();

    assert_eq!(&decrypted_cross1[..], plaintext);
    assert_eq!(&decrypted_cross2[..], plaintext);
}
