//! Tests for ChaCha20-Poly1305 AEAD cipher implementation

#[cfg(test)]
mod tests {
    use super::super::chacha20::{
        ChaCha20Key, 
        ChaCha20Nonce, 
        encrypt as chacha20_encrypt,
        decrypt as chacha20_decrypt,
    };
    use super::super::poly1305::{
        Poly1305Key,
        poly1305_mac,
        poly1305_verify,
    };
    use super::super::chacha20poly1305::{
        ChaCha20Poly1305Key,
        ChaCha20Poly1305Nonce,
        ChaCha20Poly1305,
        encrypt,
        decrypt,
    };

    #[test]
    fn test_chacha20_basic() {
        // Test vector from RFC 8439, Section 2.3.2
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let chacha_key = ChaCha20Key::new(&key).unwrap();
        let chacha_nonce = ChaCha20Nonce::new(&nonce).unwrap();

        // Encrypt
        let ciphertext = chacha20_encrypt(plaintext, &chacha_key, &chacha_nonce, 1);

        // Decrypt
        let decrypted = chacha20_decrypt(&ciphertext, &chacha_key, &chacha_nonce, 1);

        // Verify
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_poly1305_basic() {
        // Test vector from RFC 8439, Section 2.5.2
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        let message = b"Cryptographic Forum Research Group";

        let poly_key = Poly1305Key::new(&key).unwrap();
        let tag = poly1305_mac(message, &poly_key);

        // Verify
        assert!(poly1305_verify(&tag, message, &poly_key));
    }

    #[test]
    fn test_chacha20poly1305_encrypt_decrypt() {
        // Generate a random key and nonce
        let key = ChaCha20Poly1305Key::generate().unwrap();
        let nonce = ChaCha20Poly1305Nonce::generate().unwrap();
        
        // Plaintext and AAD
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let aad = b"Additional authenticated data";
        
        // Encrypt
        let ciphertext = encrypt(plaintext, Some(aad), &key, &nonce).unwrap();
        
        // Decrypt
        let decrypted = decrypt(&ciphertext, Some(aad), &key, &nonce).unwrap();
        
        // Verify
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_chacha20poly1305_authentication() {
        // Generate a random key and nonce
        let key = ChaCha20Poly1305Key::generate().unwrap();
        let nonce = ChaCha20Poly1305Nonce::generate().unwrap();
        
        // Plaintext and AAD
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let aad = b"Additional authenticated data";
        
        // Encrypt
        let mut ciphertext = encrypt(plaintext, Some(aad), &key, &nonce).unwrap();
        
        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 1;
        }
        
        // Decrypt should fail
        let result = decrypt(&ciphertext, Some(aad), &key, &nonce);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_chacha20poly1305_aad_tampering() {
        // Generate a random key and nonce
        let key = ChaCha20Poly1305Key::generate().unwrap();
        let nonce = ChaCha20Poly1305Nonce::generate().unwrap();
        
        // Plaintext and AAD
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let aad = b"Additional authenticated data";
        
        // Encrypt
        let ciphertext = encrypt(plaintext, Some(aad), &key, &nonce).unwrap();
        
        // Decrypt with modified AAD should fail
        let modified_aad = b"Modified authenticated data";
        let result = decrypt(&ciphertext, Some(modified_aad), &key, &nonce);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_chacha20poly1305_instance() {
        // Create a ChaCha20Poly1305 instance
        let key = ChaCha20Poly1305Key::generate().unwrap();
        let cipher = ChaCha20Poly1305::new(key);
        
        // Generate a nonce
        let nonce = ChaCha20Poly1305Nonce::generate().unwrap();
        
        // Plaintext and AAD
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let aad = b"Additional authenticated data";
        
        // Encrypt
        let ciphertext = cipher.encrypt(plaintext, Some(aad), &nonce).unwrap();
        
        // Decrypt
        let decrypted = cipher.decrypt(&ciphertext, Some(aad), &nonce).unwrap();
        
        // Verify
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_chacha20poly1305_empty_plaintext() {
        // Generate a random key and nonce
        let key = ChaCha20Poly1305Key::generate().unwrap();
        let nonce = ChaCha20Poly1305Nonce::generate().unwrap();
        
        // Empty plaintext
        let plaintext = b"";
        
        // Encrypt
        let ciphertext = encrypt(plaintext, None, &key, &nonce).unwrap();
        
        // Decrypt
        let decrypted = decrypt(&ciphertext, None, &key, &nonce).unwrap();
        
        // Verify
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_chacha20poly1305_rfc8439_test_vector() {
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
        let plaintext = [
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
            0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
            0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
            0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
            0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
            0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
            0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
            0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
            0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
            0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
            0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];
        
        // Expected ciphertext and tag from RFC 8439
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
        
        // Convert to our types
        let chacha_key = ChaCha20Poly1305Key::new(&key).unwrap();
        let chacha_nonce = ChaCha20Poly1305Nonce::new(&nonce).unwrap();
        
        // Encrypt
        let ciphertext = encrypt(&plaintext, Some(&aad), &chacha_key, &chacha_nonce).unwrap();
        
        // Verify ciphertext (without tag)
        assert_eq!(&ciphertext[..plaintext.len()], &expected_ciphertext[..]);
        
        // Verify tag
        assert_eq!(&ciphertext[plaintext.len()..], &expected_tag[..]);
        
        // Decrypt
        let decrypted = decrypt(&ciphertext, Some(&aad), &chacha_key, &chacha_nonce).unwrap();
        
        // Verify decrypted plaintext
        assert_eq!(&decrypted[..], &plaintext[..]);
    }
} 