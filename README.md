# QaSa - Quantum-Safe Cryptography Module

QaSa (Quantum-Safe) is a robust post-quantum cryptography implementation, featuring NIST-selected algorithms CRYSTALS-Kyber and CRYSTALS-Dilithium for quantum-safe communications.

## Features

- **CRYSTALS-Kyber**: Quantum-resistant key encapsulation mechanism (KEM)
- **CRYSTALS-Dilithium**: Quantum-resistant digital signature scheme
- **AES-GCM**: Authenticated encryption with associated data
- **Key Management**: Secure storage and handling of cryptographic keys
- **Optimisations**: Special optimisations for resource-constrained environments
- **Memory Safety**: Secure memory handling with automatic zeroisation

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
qasa = "0.0.4"
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
- **Kyber512** – NIST Level 1 (equivalent to AES-128)
- **Kyber768** – NIST Level 3 (equivalent to AES-192)
- **Kyber1024** – NIST Level 5 (equivalent to AES-256)

### Dilithium Variants
- **Dilithium2** – NIST Level 2
- **Dilithium3** – NIST Level 3
- **Dilithium5** – NIST Level 5

## Examples

The `examples/` directory contains example usage:

- `quantum_signatures.rs`: Example of using Dilithium for digital signatures
- `secure_communication.rs`: End-to-end example of quantum-safe cryptographic operations
- `oqs_correct_api.rs`: Example demonstrating proper OQS API usage

Run examples with:

```bash
cargo run --example secure_communication
cargo run --example quantum_signatures
cargo run --example oqs_correct_api
```

## Benchmarks

Performance benchmarks are available:

```bash
cargo bench
```

## Documentation

- [Security Review](security_review.md) – Security analysis and review
- [API Documentation](docs/api/crypto_api.md)
- [Security Guide](docs/api/security_guide.md)
- [Threat Model](docs/api/threat_model.md)

## Security Considerations

This implementation follows NIST post-quantum cryptography standards. For security-related questions or vulnerabilities, please review our [security policy](security_review.md).

**Note**: This is a research implementation. For production use, conduct a thorough security review and consider formal verification.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

When implementing new cryptographic functionality:
1. Place implementation code in the appropriate module directory
2. Add public API functions to the module's `mod.rs` file
3. Document all public functions with doc comments
4. Write comprehensive unit tests
5. Add benchmarks for performance-critical operations
6. Create example code demonstrating the functionality

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The NIST Post-Quantum Cryptography project
- The Open Quantum Safe project
- The Rust cryptography community 