# QaSa Crypto

[![Crates.io](https://img.shields.io/crates/v/qasa.svg)](https://crates.io/crates/qasa)
[![Documentation](https://docs.rs/qasa/badge.svg)](https://github.com/Djwarf/Qasa/blob/main/Documentation.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A robust post-quantum cryptography implementation featuring NIST-selected algorithms CRYSTALS-Kyber and CRYSTALS-Dilithium for quantum-safe communications.

## Features

- **CRYSTALS-Kyber** - Quantum-resistant key encapsulation mechanism (KEM)
- **CRYSTALS-Dilithium** - Quantum-resistant digital signature scheme  
- **AES-GCM** - Authenticated encryption with associated data
- **Key Management** - Secure storage and handling of cryptographic keys
- **Optimisations** - Special optimisations for resource-constrained environments
- **Memory Safety** - Secure memory handling with automatic zeroization

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
qasa = "0.0.1"
```

## Quick Start

### Key Encapsulation (Kyber)

```rust
use qasa::kyber::{Kyber768, KyberKeyPair};

// Generate a new key pair
let keypair = KyberKeyPair::generate()?;

// Encapsulate a shared secret
let (ciphertext, shared_secret) = keypair.encapsulate()?;

// Decapsulate the shared secret
let decapsulated_secret = keypair.decapsulate(&ciphertext)?;

assert_eq!(shared_secret, decapsulated_secret);
```

### Digital Signatures (Dilithium)

```rust
use qasa::dilithium::{Dilithium3, DilithiumKeyPair};

// Generate a new signing key pair
let keypair = DilithiumKeyPair::generate()?;

// Sign a message
let message = b"Hello, quantum-safe world!";
let signature = keypair.sign(message)?;

// Verify the signature
let is_valid = keypair.verify(message, &signature)?;
assert!(is_valid);
```

### Symmetric Encryption (AES-GCM)

```rust
use qasa::aes::{encrypt, decrypt};

let key = b"your-32-byte-key-here-for-aes256";
let plaintext = b"Secret message";

// Encrypt
let (ciphertext, nonce) = encrypt(plaintext, key)?;

// Decrypt
let decrypted = decrypt(&ciphertext, key, &nonce)?;
assert_eq!(plaintext, &decrypted[..]);
```

## Module Structure

- **kyber**: CRYSTALS-Kyber implementation for quantum-resistant key encapsulation
- **dilithium**: CRYSTALS-Dilithium implementation for quantum-resistant digital signatures  
- **aes**: AES-GCM implementation for symmetric encryption
- **key_management**: Secure key storage and rotation mechanisms
- **secure_memory**: Memory protection utilities for sensitive data
- **utils**: Cryptographic utilities and helper functions

## Security Levels

### Kyber Variants
- **Kyber512** - NIST Level 1 (equivalent to AES-128)
- **Kyber768** - NIST Level 3 (equivalent to AES-192) 
- **Kyber1024** - NIST Level 5 (equivalent to AES-256)

### Dilithium Variants  
- **Dilithium2** - NIST Level 2
- **Dilithium3** - NIST Level 3
- **Dilithium5** - NIST Level 5

## Examples

The crate includes several examples demonstrating different use cases:

```bash
# Run the secure communication example
cargo run --example secure_communication

# Run the digital signatures example  
cargo run --example quantum_signatures

# Run the OQS API example
cargo run --example oqs_correct_api
```

## Benchmarks

Performance benchmarks are available:

```bash
cargo bench
```

## Features

- `lean` - Enable optimised implementations for constrained environments
- `simd` - Enable SIMD optimisations when available
- `hardware-acceleration` - Enable hardware acceleration when available
- `debug` - Enable additional debugging and profiling features

## Minimum Supported Rust Version (MSRV)

This crate requires Rust 1.60 or later.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security

This implementation follows NIST post-quantum cryptography standards. For security-related questions or vulnerabilities, please review our [security policy](security_review.md).

## Acknowledgments

- NIST Post-Quantum Cryptography Project
- Open Quantum Safe Project  
- CRYSTALS Team (Kyber and Dilithium algorithms) 