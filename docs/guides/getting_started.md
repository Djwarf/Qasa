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
qasa = "0.0.3
```

## Building from Source

### 1. Clone the Repository

```bash
git clone https://github.com/Djwarf/Qasa.git
cd Qasa
```

### 2. Build the Cryptography Module

```bash
cd src/crypto
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

// Generate Kyber key pair for key encapsulation
let kyber_keypair = KyberKeyPair::generate(KyberVariant::Kyber768)?;

// Generate Dilithium key pair for digital signatures
let dilithium_keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)?;
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

```rust
// Sign a message
let message = b"Hello, quantum-safe world!";
let signature = dilithium_keypair.sign(message)?;

// Verify a signature
let is_valid = dilithium_keypair.public_key()
    .verify(message, &signature)?;
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

## Examples

The `examples/` directory contains complete usage examples:

### Basic Cryptographic Operations

```bash
cd src/crypto
cargo run --example quantum_signatures
cargo run --example secure_communication
```

### Optimized Operations for Constrained Environments

```bash
cargo run --example optimized_signatures
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
aes_key_size = 256

[performance]
simd = true
hardware_accel = true

[memory]
usage_mode = "optimized"
max_memory_per_op = 1048576
```

## Performance Optimization

### Building for Performance

```bash
# Enable all optimizations
export RUSTFLAGS="-C target-cpu=native -C opt-level=3"
cargo build --release --features "optimized,simd"
```

### Memory-Constrained Environments

```bash
# Build with minimal features
cargo build --release --no-default-features --features "lean"
```

## Security Best Practices

1. **Always use release builds for production**
2. **Enable secure memory handling**
3. **Regularly rotate cryptographic keys**
4. **Backup keys securely with strong passwords**
5. **Monitor for side-channel attacks**
6. **Keep the crypto module updated**

## Next Steps

- Read the [Crypto Module README](../../src/crypto/README.md) for detailed module information
- Review the [Security Guide](../api/security_guide.md) for implementation best practices
- Study the [Threat Model](../api/threat_model.md) to understand security considerations
- Explore the [API Documentation](../api/crypto_api.md) for detailed function reference

## Getting Help

If you encounter issues:

1. Check the [Security Review](../../src/crypto/security_review.md) for known considerations
2. Review the examples in `src/crypto/examples/`
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