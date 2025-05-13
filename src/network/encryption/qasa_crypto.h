#ifndef QASA_CRYPTO_H
#define QASA_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// Return codes
// 0: Success
// -1: Error

// Initialize the cryptography module
int qasa_crypto_init(char **error_msg);

// Free a string allocated by the library
void qasa_free_string(char *str);

// Free a byte buffer allocated by the library
void qasa_free_bytes(uint8_t *bytes);

// Kyber functions

// Generate a Kyber key pair
int qasa_kyber_keygen(
    int variant,                 // 512, 768, or 1024
    uint8_t *public_key,         // Output: public key buffer
    int *public_key_size,        // Input/output: size of public key buffer
    uint8_t *private_key,        // Output: private key buffer
    int *private_key_size,       // Input/output: size of private key buffer
    char **error_msg             // Output: error message on failure
);

// Kyber encapsulate (generate and encrypt a shared secret)
int qasa_kyber_encapsulate(
    int variant,                 // 512, 768, or 1024
    const uint8_t *public_key,   // Input: public key
    int public_key_size,         // Input: size of public key
    uint8_t *ciphertext,         // Output: ciphertext buffer
    int *ciphertext_size,        // Input/output: size of ciphertext buffer
    uint8_t *shared_secret,      // Output: shared secret buffer
    int *shared_secret_size,     // Input/output: size of shared secret buffer
    char **error_msg             // Output: error message on failure
);

// Kyber decapsulate (decrypt a shared secret)
int qasa_kyber_decapsulate(
    int variant,                 // 512, 768, or 1024
    const uint8_t *private_key,  // Input: private key
    int private_key_size,        // Input: size of private key
    const uint8_t *ciphertext,   // Input: ciphertext
    int ciphertext_size,         // Input: size of ciphertext
    uint8_t *shared_secret,      // Output: shared secret buffer
    int *shared_secret_size,     // Input/output: size of shared secret buffer
    char **error_msg             // Output: error message on failure
);

// Dilithium functions

// Generate a Dilithium key pair
int qasa_dilithium_keygen(
    int variant,                 // 2, 3, or 5
    uint8_t *public_key,         // Output: public key buffer
    int *public_key_size,        // Input/output: size of public key buffer
    uint8_t *private_key,        // Output: private key buffer
    int *private_key_size,       // Input/output: size of private key buffer
    char **error_msg             // Output: error message on failure
);

// Dilithium sign a message
int qasa_dilithium_sign(
    int variant,                 // 2, 3, or 5
    const uint8_t *private_key,  // Input: private key
    int private_key_size,        // Input: size of private key
    const uint8_t *message,      // Input: message to sign
    int message_size,            // Input: size of message
    uint8_t *signature,          // Output: signature buffer
    int *signature_size,         // Input/output: size of signature buffer
    char **error_msg             // Output: error message on failure
);

// Dilithium verify a signature
int qasa_dilithium_verify(
    int variant,                 // 2, 3, or 5
    const uint8_t *public_key,   // Input: public key
    int public_key_size,         // Input: size of public key
    const uint8_t *message,      // Input: message that was signed
    int message_size,            // Input: size of message
    const uint8_t *signature,    // Input: signature to verify
    int signature_size,          // Input: size of signature
    char **error_msg             // Output: error message on failure
);

// AES-GCM functions

// AES-GCM encrypt
int qasa_aes_gcm_encrypt(
    const uint8_t *key,          // Input: encryption key (32 bytes)
    int key_size,                // Input: size of key
    const uint8_t *plaintext,    // Input: plaintext to encrypt
    int plaintext_size,          // Input: size of plaintext
    const uint8_t *associated_data, // Input: additional authenticated data
    int associated_data_size,    // Input: size of additional data
    uint8_t *ciphertext,         // Output: ciphertext buffer
    int *ciphertext_size,        // Input/output: size of ciphertext buffer
    uint8_t *nonce,              // Output: nonce buffer
    int *nonce_size,             // Input/output: size of nonce buffer
    char **error_msg             // Output: error message on failure
);

// AES-GCM decrypt
int qasa_aes_gcm_decrypt(
    const uint8_t *key,          // Input: encryption key (32 bytes)
    int key_size,                // Input: size of key
    const uint8_t *ciphertext,   // Input: ciphertext to decrypt
    int ciphertext_size,         // Input: size of ciphertext
    const uint8_t *nonce,        // Input: nonce
    int nonce_size,              // Input: size of nonce
    const uint8_t *associated_data, // Input: additional authenticated data
    int associated_data_size,    // Input: size of additional data
    uint8_t *plaintext,          // Output: plaintext buffer
    int *plaintext_size,         // Input/output: size of plaintext buffer
    char **error_msg             // Output: error message on failure
);

#ifdef __cplusplus
}
#endif

#endif /* QASA_CRYPTO_H */ 