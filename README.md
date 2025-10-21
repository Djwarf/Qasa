# QaSa - Quantum-Safe Cryptography Module

[![Crates.io](https://img.shields.io/crates/v/qasa.svg)](https://crates.io/crates/qasa)
[![Documentation](https://docs.rs/qasa/badge.svg)](https://docs.rs/qasa)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust Version](https://img.shields.io/badge/rust-1.60%2B-blue.svg)](https://www.rust-lang.org)

QaSa (Quantum-Safe) is a robust post-quantum cryptography implementation, featuring NIST-selected algorithms CRYSTALS-Kyber and CRYSTALS-Dilithium for quantum-safe communications.

> ⚠️ **Important:** Version 0.1.0 includes breaking changes from v0.0.3. The ChaCha20-Poly1305 implementation has been fixed to comply with RFC 8439. Data encrypted with v0.0.3 cannot be decrypted with v0.1.0. See [CHANGELOG.md](CHANGELOG.md) for migration details.

## Features

- **CRYSTALS-Kyber**: Quantum-resistant key encapsulation mechanism (KEM)
- **CRYSTALS-Dilithium**: Quantum-resistant digital signature scheme
- **SPHINCS+**: Hash-based quantum-resistant digital signature scheme
- **AES-GCM**: Authenticated encryption with associated data
- **Key Management**: Secure storage and handling of cryptographic keys
- **HSM Integration**: Hardware Security Module support via PKCS#11
- **WebAssembly Support**: Browser and Node.js compatibility
- **Python Bindings**: Easy integration with Python applications
- **Formal Verification**: Mathematical verification of security properties
- **Optimisations**: Special optimisations for resource-constrained environments
- **Memory Safety**: Secure memory handling with automatic zeroisation

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
qasa = "0.1.0"
```

### Optional Features

QaSa supports several optional features that can be enabled based on your needs:

```toml
[dependencies]
qasa = { version = "0.1.0", features = ["simd", "python", "wasm"] }
```

Available features:
- `simd`: Enable SIMD optimizations (enabled by default)
- `python`: Enable Python bindings via PyO3
- `wasm`: Enable WebAssembly support
- `formal-verification`: Enable formal verification tools
- `hardware-acceleration`: Enable hardware acceleration when available
- `lean`: Enable optimized implementations for constrained environments

## Quick Start

### Key Encapsulation (Kyber)

```rust
use qasa::kyber::{KyberVariant, KyberKeyPair};

// Generate a new key pair
let keypair = KyberKeyPair::generate(KyberVariant::Kyber768)?;

// Encapsulate a shared secret
let (ciphertext, shared_secret) = keypair.encapsulate()?;

// Decapsulate the shared secret
let decapsulated_secret = keypair.decapsulate(&ciphertext)?;

assert_eq!(shared_secret, decapsulated_secret);
```

### Digital Signatures (Dilithium)

```rust
use qasa::dilithium::{DilithiumVariant, DilithiumKeyPair};

// Generate a new signing key pair
let keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)?;

// Sign a message
let message = b"Hello, quantum-safe world!";
let signature = keypair.sign(message)?;

// Verify the signature
let is_valid = keypair.verify(message, &signature)?;
assert!(is_valid);
```

### Digital Signatures (SPHINCS+)

```rust
use qasa::sphincsplus::{SphincsVariant, SphincsKeyPair, CompressionLevel};

// Generate a new signing key pair
let keypair = SphincsKeyPair::generate(SphincsVariant::Sphincs192f)?;

// Sign a message
let message = b"Hello, quantum-safe world!";
let signature = keypair.sign(message)?;

// Verify the signature
let is_valid = keypair.verify(message, &signature)?;
assert!(is_valid);

// For reduced signature size, use compression
let compressed = keypair.sign_compressed(message, CompressionLevel::Medium)?;
let is_valid = keypair.verify_compressed(message, &compressed)?;
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

### HSM Integration

```rust
use qasa::key_management::{HsmProvider, HsmConfig, HsmKeyAttributes};

// Configure HSM connection
let config = HsmConfig {
    library_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
    slot_id: Some(0),
    token_label: Some("qasa".to_string()),
    user_pin: Some(SecureBytes::from(b"1234".to_vec())),
    provider_config: HashMap::new(),
};

// Generate key in HSM
let attributes = HsmKeyAttributes {
    label: "dilithium-signing-key".to_string(),
    id: vec![1, 2, 3, 4],
    extractable: false,
    sensitive: true,
    allowed_operations: vec![HsmOperation::Sign, HsmOperation::Verify],
    provider_attributes: HashMap::new(),
};

// Generate key in HSM
let key_handle = generate_key_in_hsm(
    HsmProvider::Pkcs11,
    config.clone(),
    HsmKeyType::Dilithium(DilithiumVariant::Dilithium3),
    attributes
)?;

// Sign using HSM-protected key
let message = b"Sign this with HSM-protected key";
let signature = sign_with_hsm(
    HsmProvider::Pkcs11,
    config.clone(),
    &key_handle,
    message,
    HsmMechanism::Dilithium(DilithiumVariant::Dilithium3)
)?;
```

### WebAssembly Support

```rust
// In your Cargo.toml
// [dependencies]
// qasa = { version = "0.1.0", features = ["wasm"] }

// In your wasm module
use qasa::prelude::*;

// Configure WASM-specific options
let wasm_config = WasmConfig {
    use_simd: true,
    memory_limit: 16 * 1024 * 1024, // 16MB
    enable_threading: false,
};

// Initialize WASM environment
init_wasm(Some(wasm_config))?;

// Use WASM-optimized implementations
let key_pair = KyberKeyPair::generate_optimized(
    KyberVariant::Kyber768,
    OptimizationTarget::Wasm
)?;
```

### Python Bindings

```python
# First, install the Python package
# pip install qasa

import qasa

# Initialize the module
qasa.init()

# Generate a Kyber key pair
public_key, secret_key = qasa.kyber_keygen(768)

# Encapsulate a shared secret
ciphertext, shared_secret = qasa.kyber_encapsulate(768, public_key)

# Decapsulate the shared secret
decapsulated = qasa.kyber_decapsulate(768, secret_key, ciphertext)
```

### Formal Verification

```rust
use qasa::security::{FormalVerifier, VerificationProperty};

// Create a formal verifier
let verifier = FormalVerifier::default();

// Verify constant-time implementation
let result = verifier.verify_kyber(
    KyberVariant::Kyber768,
    VerificationProperty::ConstantTime
)?;

// Check verification result
if result.verified {
    println!("Verification passed with confidence: {}", result.confidence);
} else {
    println!("Verification failed: {:?}", result.details);
}
```

## Module Structure

- **kyber**: CRYSTALS-Kyber implementation for quantum-resistant key encapsulation
- **dilithium**: CRYSTALS-Dilithium implementation for quantum-resistant digital signatures
- **sphincsplus**: SPHINCS+ implementation for hash-based quantum-resistant digital signatures
- **aes**: AES-GCM implementation for symmetric encryption
- **key_management**: Secure key storage, rotation mechanisms, and HSM integration
- **secure_memory**: Memory protection utilities for sensitive data
- **utils**: Cryptographic utilities and helper functions
- **simd**: SIMD optimizations for various platforms including WebAssembly
- **security**: Formal verification tools and security properties
- **ffi**: Foreign function interfaces including Python bindings

## Security Levels

### Kyber Variants
- **Kyber512** – NIST Level 1 (equivalent to AES-128)
- **Kyber768** – NIST Level 3 (equivalent to AES-192)
- **Kyber1024** – NIST Level 5 (equivalent to AES-256)

### Dilithium Variants
- **Dilithium2** – NIST Level 2
- **Dilithium3** – NIST Level 3
- **Dilithium5** – NIST Level 5

### SPHINCS+ Variants
- **Sphincs128f** – NIST Level 1, optimized for speed
- **Sphincs128s** – NIST Level 1, optimized for size
- **Sphincs192f** – NIST Level 3, optimized for speed
- **Sphincs192s** – NIST Level 3, optimized for size
- **Sphincs256f** – NIST Level 5, optimized for speed
- **Sphincs256s** – NIST Level 5, optimized for size

## Examples

The `examples/` directory contains example usage:

- `quantum_signatures.rs`: Example of using Dilithium for digital signatures
- `secure_communication.rs`: End-to-end example of quantum-safe cryptographic operations
- `sphincs_signatures.rs`: Example of using SPHINCS+ for hash-based signatures
- `hsm_operations.rs`: Example of using Hardware Security Modules
- `wasm_crypto.rs`: Example of WebAssembly integration
- `python_bindings.py`: Example of Python bindings usage

Run examples with:

```bash
cargo run --example secure_communication
cargo run --example quantum_signatures
cargo run --example sphincs_signatures
cargo run --example hsm_operations
cargo run --example wasm_crypto --features wasm
python examples/python_bindings.py
```

## Benchmarks

Performance benchmarks are available:

```bash
cargo bench
```

## Documentation

- [Getting Started](docs/guides/getting_started.md) - Quick start guide
- [Security Review](security_review.md) – Security analysis and review
- [API Documentation](docs/api/crypto_api.md) - Detailed API reference
- [Security Guide](docs/api/security_guide.md) - Security best practices
- [Threat Model](docs/api/threat_model.md) - Comprehensive threat model

## Security Considerations

This implementation follows NIST post-quantum cryptography standards. For security-related questions or vulnerabilities, please review our [security policy](security_review.md).

**Note**: While this implementation has undergone formal verification for key security properties, we recommend a thorough security review before production use in critical applications.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

When implementing new cryptographic functionality:
1. Place implementation code in the appropriate module directory
2. Add public API functions to the module's `mod.rs` file
3. Document all public functions with doc comments
4. Write comprehensive unit tests
5. Add benchmarks for performance-critical operations
6. Create example code demonstrating the functionality
7. Add formal verification where appropriate

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The NIST Post-Quantum Cryptography project
- The Open Quantum Safe project
- The Rust cryptography community 