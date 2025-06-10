# QaSa - Quantum-Safe Cryptography Module

QaSa (Quantum-Safe) is a post-quantum cryptography implementation that provides protection against quantum computer attacks using NIST-selected post-quantum algorithms.

## Features

- **CRYSTALS-Kyber**: Quantum-resistant key encapsulation mechanism (KEM)
- **CRYSTALS-Dilithium**: Quantum-resistant digital signature scheme
- **AES-GCM**: Authenticated encryption with associated data
- **Key Management**: Secure storage and handling of cryptographic keys
- **Optimisations**: Special optimisations for resource-constrained environments

## Getting Started

### Prerequisites

- Rust 1.60 or later
- A C compiler (GCC or Clang)

### Building the Crypto Module

1. Navigate to the crypto directory:
   ```bash
   cd src/crypto
   ```

2. Build the crypto module:
   ```bash
   cargo build --release
   ```

3. Run tests:
   ```bash
   cargo test
   ```

4. Run benchmarks:
   ```bash
   cargo bench
   ```

## Architecture

The cryptography module is organised into the following sub-modules:

- **kyber**: CRYSTALS-Kyber implementation for quantum-resistant key encapsulation
- **dilithium**: CRYSTALS-Dilithium implementation for quantum-resistant digital signatures  
- **aes**: AES-GCM implementation for symmetric encryption
- **key_management**: Key management system for storing and loading keys
- **security**: Security utilities and secure memory handling
- **error.rs**: Common error types for the cryptography module
- **utils.rs**: Utilities for cryptographic operations

## Optimisations for Resource-Constrained Environments

The cryptography module includes special optimisations for resource-constrained environments, particularly for the Dilithium signature scheme:

### Memory-Efficient Variant Selection

The `DilithiumVariant::for_constrained_environment()` function helps select the most appropriate variant based on available memory and security requirements:

```rust
// Select the appropriate variant for a device with limited memory
let variant = DilithiumVariant::for_constrained_environment(
    2, // Minimum security level
    8  // Available memory in KB
);
```

### Lazy Initialisation

The `LeanDilithium` implementation uses lazy initialisation to minimise memory usage:

```rust
// Create a lean implementation that doesn't initialise resources immediately
let mut lean = LeanDilithium::new(DilithiumVariant::Dilithium2);

// Resources are only allocated when needed
let signature = lean.sign(message, &secret_key)?;

// Resources can be explicitly released when no longer needed
lean.release_resources();
```

### Streamlined Operations

For one-off signing or verification operations, streamlined functions are provided:

```rust
// Sign a message without maintaining state
let signature = lean_sign(message, &secret_key, DilithiumVariant::Dilithium2)?;

// Verify a signature without maintaining state
let is_valid = lean_verify(message, &signature, &public_key, DilithiumVariant::Dilithium2)?;
```

### Batch Verification

For efficient verification of multiple signatures:

```rust
// Create a batch of messages, signatures, and public keys to verify
let batch = vec![
    (message1, signature1, public_key1, DilithiumVariant::Dilithium2),
    (message2, signature2, public_key2, DilithiumVariant::Dilithium3),
];

// Verify all signatures in a memory-efficient way
let results = lean_verify_batch(&batch)?;
```

## Performance

Benchmark results show that the optimised implementations maintain performance comparable to the standard implementations:

| Operation | Standard Implementation | Optimised Implementation |
|-----------|-------------------------|--------------------------|
| Dilithium2 Sign | ~39.3 µs | ~39.2 µs |
| Dilithium2 Verify | ~14.7 µs | ~14.7 µs |
| Dilithium3 Sign | ~63.5 µs | ~63.2 µs |
| Dilithium3 Verify | ~24.7 µs | ~24.7 µs |
| Dilithium5 Sign | ~76.9 µs | ~78.8 µs |
| Dilithium5 Verify | ~38.7 µs | ~39.2 µs |

## Documentation

For detailed documentation, see:

- [Crypto Module README](src/crypto/README.md) - Module overview and structure
- [Security Review](src/crypto/security_review.md) - Security analysis and review
- [API Documentation](docs/api/crypto_api.md) - API documentation
- [Security Guide](docs/api/security_guide.md) - Security implementation guide
- [Threat Model](docs/api/threat_model.md) - Threat model analysis

## Examples

The `src/crypto/examples/` directory contains example usage:

- `quantum_signatures.rs`: Example of using Dilithium for digital signatures
- `optimized_signatures.rs`: Example of using optimised Dilithium implementations
- `secure_communication.rs`: End-to-end example of quantum-safe cryptographic operations

## Security Considerations

This is a post-quantum cryptography implementation using NIST-selected algorithms. Key security features:

- Post-quantum key exchange with CRYSTALS-Kyber
- Post-quantum signatures with CRYSTALS-Dilithium
- AES-GCM for symmetric encryption
- Secure key management and storage
- Protection against quantum computer attacks

**Note**: This is a research implementation. For production use, conduct a thorough security review.

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

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The NIST Post-Quantum Cryptography project
- The Open Quantum Safe project
- The Rust cryptography community 