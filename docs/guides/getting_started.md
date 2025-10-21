# Getting Started with QaSa Cryptography Module

This guide will help you get started with the QaSa post-quantum cryptography module.

## Prerequisites

Before you begin, ensure you have the following installed:

- Rust 1.60+ with Cargo
- Git
- A C compiler (GCC or Clang for building native dependencies)

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

## Building from Source

### 1. Clone the Repository

```bash
git clone https://github.com/Djwarf/Qasa.git
cd Qasa
```

### 2. Build the Cryptography Module

```bash
cargo build --release
```

### 3. Run Tests

```bash
cargo test
```

### 4. Run Benchmarks

```bash
cargo bench
```

## Using the Crypto Module

### Key Generation

```rust
use qasa::kyber::{KyberKeyPair, KyberVariant};
use qasa::dilithium::{DilithiumKeyPair, DilithiumVariant};
use qasa::sphincsplus::{SphincsKeyPair, SphincsVariant};

// Generate Kyber key pair for key encapsulation
let kyber_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)?;

// Generate Dilithium key pair for digital signatures
let dilithium_keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)?;

// Generate SPHINCS+ key pair for hash-based signatures
let sphincs_keypair = SphincsKeyPair::generate(SphincsVariant::Sphincs192f)?;
```

### Key Encapsulation

```rust
// Encapsulate a shared secret
let (ciphertext, shared_secret) = kyber_keypair.public_key()
    .encapsulate()?;

// Decapsulate the shared secret
let decapsulated_secret = kyber_keypair
    .decapsulate(&ciphertext)?;
```

### Digital Signatures

#### Using Dilithium

```rust
// Sign a message
let message = b"Hello, quantum-safe world!";
let signature = dilithium_keypair.sign(message)?;

// Verify a signature
let is_valid = dilithium_keypair.public_key()
    .verify(message, &signature)?;
```

#### Using SPHINCS+

```rust
// Sign a message
let message = b"Hello, quantum-safe world!";
let signature = sphincs_keypair.sign(message)?;

// Verify a signature
let is_valid = sphincs_keypair.public_key()
    .verify(message, &signature)?;

// For reduced signature size, use compression
let compressed = sphincs_keypair.sign_compressed(message, CompressionLevel::Medium)?;
let is_valid = sphincs_keypair.public_key()
    .verify_compressed(message, &compressed)?;
```

### Symmetric Encryption

```rust
use qasa::aes;

// Encrypt data with AES-GCM
let plaintext = b"Confidential message";
let (ciphertext, nonce) = aes::encrypt(plaintext, &shared_secret, None)?;

// Decrypt data
let decrypted = aes::decrypt(&ciphertext, &shared_secret, &nonce, None)?;
```

## Key Management

### Secure Key Storage

```rust
use qasa::key_management::{KeyStore, StorageConfig};

// Create a key store
let config = StorageConfig::new("~/.qasa/keys");
let mut key_store = KeyStore::new(config)?;

// Store keys securely
key_store.store_keypair("my-kyber-key", &kyber_keypair, Some("password"))?;
key_store.store_signing_keypair("my-dilithium-key", &dilithium_keypair, Some("password"))?;
key_store.store_signing_keypair("my-sphincs-key", &sphincs_keypair, Some("password"))?;

// Load keys
let loaded_keypair = key_store.load_keypair("my-kyber-key", Some("password"))?;
```

### Key Rotation

```rust
use qasa::key_management::KeyRotation;

// Set up automatic key rotation
let rotation_config = KeyRotation::new()
    .interval_days(30)
    .backup_previous(true);

key_store.enable_rotation("my-kyber-key", rotation_config)?;
```

## Hardware Security Module (HSM) Integration

QaSa now supports integration with Hardware Security Modules (HSMs) for enhanced security:

```rust
use qasa::key_management::{HsmProvider, HsmConfig, HsmKeyAttributes};

// Create HSM configuration
let config = HsmConfig {
    library_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
    slot_id: Some(0),
    token_label: Some("qasa".to_string()),
    user_pin: Some(SecureBytes::from(b"1234".to_vec())),
    provider_config: HashMap::new(),
};

// Connect to HSM
let mut hsm = connect_hsm(HsmProvider::SoftHsm, config)?;

// Generate key in HSM
let attributes = HsmKeyAttributes {
    label: "my-dilithium-key".to_string(),
    id: vec![1, 2, 3, 4],
    extractable: false,
    sensitive: true,
    allowed_operations: vec![HsmOperation::Sign, HsmOperation::Verify],
    provider_attributes: HashMap::new(),
};

let key_handle = generate_key_in_hsm(
    HsmProvider::SoftHsm,
    config.clone(),
    HsmKeyType::Dilithium(DilithiumVariant::Dilithium3),
    attributes
)?;

// Sign using HSM
let signature = sign_with_hsm(
    HsmProvider::SoftHsm,
    config.clone(),
    &key_handle,
    message,
    HsmMechanism::Dilithium(DilithiumVariant::Dilithium3)
)?;
```

## WebAssembly Support

QaSa now includes WebAssembly (WASM) support for browser and Node.js environments:

```rust
// In your Cargo.toml
// [dependencies]
// qasa = { version = "0.1.0", features = ["wasm"] }

// In your wasm module
use qasa::prelude::*;

// The library will automatically detect WASM environment
// and use appropriate optimizations
let keypair = KyberKeyPair::generate(KyberVariant::Kyber768)?;
```

## Python Bindings

QaSa provides Python bindings for easy integration with Python applications:

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

# Generate a Dilithium key pair
public_key, secret_key = qasa.dilithium_keygen(3)

# Sign a message
signature = qasa.dilithium_sign(3, secret_key, b"Hello, quantum-safe world!")

# Verify a signature
is_valid = qasa.dilithium_verify(3, public_key, b"Hello, quantum-safe world!", signature)
```

## Formal Verification

QaSa includes formal verification tools to verify security properties:

```rust
use qasa::security::{FormalVerifier, VerificationProperty};

// Create a formal verifier with default configuration
let verifier = FormalVerifier::default();

// Verify constant-time implementation of Kyber
let result = verifier.verify_kyber(
    KyberVariant::Kyber768,
    VerificationProperty::ConstantTime
)?;

// Check verification result
if result.verified {
    println!("Kyber constant-time verification passed with confidence: {}", 
             result.confidence);
} else {
    println!("Verification failed: {:?}", result.details);
}

// Generate a comprehensive verification report
let properties = vec![
    VerificationProperty::ConstantTime,
    VerificationProperty::AlgorithmCorrectness,
    VerificationProperty::ProtocolSecurity
];

let report = generate_verification_report("Kyber768", &properties, None)?;
```

## Examples

The `examples/` directory contains complete usage examples:

### Basic Cryptographic Operations

```bash
cargo run --example quantum_signatures
cargo run --example secure_communication
cargo run --example sphincs_signatures
```

### Optimized Operations for Constrained Environments

```bash
cargo run --example optimized_signatures
```

### Platform-Specific Examples

```bash
# WebAssembly example
cargo run --example wasm_crypto --features wasm

# HSM integration example
cargo run --example hsm_operations

# Python bindings example
python examples/python_bindings.py
```

## Configuration

Create a `crypto.toml` configuration file:

```toml
[security]
secure_memory = true
constant_time = true
zeroize_on_drop = true

[algorithms]
kyber_variant = "Kyber768"
dilithium_variant = "Dilithium3"
sphincsplus_variant = "Sphincs192f"
aes_key_size = 256

[performance]
simd = true
hardware_accel = true
wasm_simd = true

[memory]
usage_mode = "optimized"
max_memory_per_op = 1048576

[hsm]
provider = "SoftHsm"
library_path = "/usr/lib/softhsm/libsofthsm2.so"
slot_id = 0
```

## Performance Optimization

### Building for Performance

```bash
# Enable all optimizations
export RUSTFLAGS="-C target-cpu=native -C opt-level=3"
cargo build --release --features "optimized,simd,hardware-acceleration"
```

### Memory-Constrained Environments

```bash
# Build with minimal features
cargo build --release --no-default-features --features "lean"
```

### WebAssembly Optimization

```bash
# Build optimized WASM module
cargo build --target wasm32-unknown-unknown --release --features "wasm"
wasm-opt -O3 -o optimized.wasm target/wasm32-unknown-unknown/release/qasa.wasm
```

## Security Best Practices

1. **Always use release builds for production**
2. **Enable secure memory handling**
3. **Regularly rotate cryptographic keys**
4. **Backup keys securely with strong passwords**
5. **Monitor for side-channel attacks**
6. **Keep the crypto module updated**
7. **Use HSMs for storing critical keys when possible**
8. **Verify formal security properties in security-critical applications**

## Next Steps

- Read the [README](../../README.md) for detailed module information
- Review the [Security Guide](../api/security_guide.md) for implementation best practices
- Study the [Threat Model](../api/threat_model.md) to understand security considerations
- Explore the [API Documentation](../api/crypto_api.md) for detailed function reference

## Getting Help

If you encounter issues:

1. Check the [Security Review](../../security_review.md) for known considerations
2. Review the examples in `examples/`
3. Search for similar issues on our GitHub repository
4. Consult the comprehensive API documentation

## Contributing

We welcome contributions! See the [Contributing Guide](../../CONTRIBUTING.md) to learn how you can help improve the QaSa cryptography module.

When contributing to the crypto module:

1. Ensure all changes maintain security properties
2. Add comprehensive tests for new functionality
3. Update documentation for API changes
4. Consider performance impact on constrained environments
5. Follow secure coding practices for cryptographic implementations 