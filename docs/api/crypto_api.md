# QaSa Cryptography API

This document provides an overview of the QaSa cryptography module API.

## Module Overview

The cryptography module provides quantum-resistant cryptographic primitives for:

- Key encapsulation (using CRYSTALS-Kyber)
- Digital signatures (using CRYSTALS-Dilithium)
- Symmetric encryption (using AES-GCM)
- Key management

## Installation

```toml
[dependencies]
qasa = "0.0.3"
```

## Core Types

### `KyberKeyPair`

Represents a CRYSTALS-Kyber key pair for key encapsulation.

```rust
pub struct KyberKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: KyberVariant,
}
```

### `KyberVariant`

Enum representing different security levels of Kyber.

```rust
pub enum KyberVariant {
    Kyber512,  // NIST security level 1
    Kyber768,  // NIST security level 3, recommended
    Kyber1024, // NIST security level 5
}
```

### `DilithiumKeyPair`

Represents a CRYSTALS-Dilithium key pair for digital signatures.

```rust
pub struct DilithiumKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: DilithiumVariant,
}
```

### `DilithiumVariant`

Enum representing different security levels of Dilithium.

```rust
pub enum DilithiumVariant {
    Dilithium2,  // NIST security level 2
    Dilithium3,  // NIST security level 3, recommended
    Dilithium5,  // NIST security level 5
}
```

## Key Encapsulation (Kyber)

### Generating a Key Pair

```rust
// Generate a new Kyber key pair
let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768)?;
```

### Encapsulating a Shared Secret

```rust
// Encapsulate a shared secret using a public key
let (ciphertext, shared_secret) = key_pair.public_key()
    .encapsulate()?;
```

### Decapsulating a Shared Secret

```rust
// Decapsulate a shared secret using a ciphertext
let shared_secret = key_pair
    .decapsulate(&ciphertext)?;
```

## Digital Signatures (Dilithium)

### Generating a Key Pair

```rust
// Generate a new Dilithium key pair
let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)?;
```

### Signing a Message

```rust
// Sign a message
let signature = key_pair.sign(message)?;
```

### Verifying a Signature

```rust
// Verify a signature
let is_valid = key_pair.public_key()
    .verify(message, &signature)?;
```

## Symmetric Encryption (AES-GCM)

### Encrypting Data

```rust
// Encrypt data using AES-GCM
let (ciphertext, nonce) = aes::encrypt(plaintext, &key, Some(associated_data))?;
```

### Decrypting Data

```rust
// Decrypt data using AES-GCM
let plaintext = aes::decrypt(&ciphertext, &key, &nonce, Some(associated_data))?;
```

## Key Management

### Storing Keys

```rust
// Store a key with password protection
key_management::store_key("my-key", &key_pair, "password")?;
```

### Loading Keys

```rust
// Load a key with password
let key_pair = key_management::load_key("my-key", "password")?;
```

### Rotating Keys

```rust
// Rotate a key
let new_key_pair = key_management::rotate_key("my-key", "password")?;
```

## Error Handling

All functions return a `Result` type with `CryptoError` for error cases:

```rust
pub enum CryptoError {
    OqsError(String),
    KeyGenerationError(String),
    EncapsulationError(String),
    DecapsulationError(String),
    SignatureGenerationError(String),
    SignatureVerificationError(String),
    EncryptionError(String),
    DecryptionError(String),
    SerializationError(String),
    KeyManagementError(String),
    IoError(std::io::Error),
    InvalidParameterError(String),
    RandomGenerationError(String),
}
```

## Utilities

### Random Bytes Generation

```rust
// Generate random bytes
let random_data = utils::random_bytes(32)?;
```

### Constant-Time Comparison

```rust
// Compare two byte slices in constant time
let is_equal = utils::constant_time_eq(&bytes1, &bytes2);
```

### Secure Memory Zeroing

```rust
// Zero out sensitive data from memory
utils::secure_zero(&mut sensitive_data);
```

## Example: Complete Encryption Flow

```rust
// Generate a Kyber key pair
let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768)?;

// Generate a shared secret
let (ciphertext, shared_secret) = key_pair.encapsulate()?;

// Use the shared secret for AES encryption
let message = b"Hello, quantum-safe world!";
let (encrypted, nonce) = aes::encrypt(message, &shared_secret, b"")?;

// Send the ciphertext and encrypted message to the recipient
// ...

// Recipient decapsulates the shared secret
let shared_secret = recipient_key_pair.decapsulate(&ciphertext)?;

// Recipient decrypts the message
let decrypted = aes::decrypt(&encrypted, &shared_secret, &nonce, b"")?;
```