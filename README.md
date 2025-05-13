# QaSa - Quantum-Safe Chat Application

QaSa is a secure end-to-end encrypted chat application that uses post-quantum cryptography to provide protection against quantum computer attacks.

## Project Overview

This project implements:

- **Post-Quantum Cryptography** using NIST-selected algorithms:
  - CRYSTALS-Kyber for key encapsulation (replacing traditional Diffie-Hellman)
  - CRYSTALS-Dilithium for digital signatures (replacing RSA/ECDSA)
  - AES-GCM for symmetric encryption
  
- **Secure P2P Networking**:
  - Peer-to-peer communication using libp2p
  - End-to-end encryption for all messages
  - Secure message exchange protocol
  - Distributed peer discovery and management

## Repository Structure

```
QaSa/
├── docs/               # Documentation
│   ├── api/            # API documentation
│   ├── guides/         # User and developer guides
│   └── protocol/       # Protocol specifications
├── src/                # Source code
│   ├── crypto/         # Cryptography module (Rust)
│   │   ├── kyber/      # CRYSTALS-Kyber implementation
│   │   ├── dilithium/  # CRYSTALS-Dilithium implementation
│   │   ├── aes/        # AES-GCM implementation
│   │   └── key_management/ # Key management system
│   ├── network/        # Network module (Go)
│   │   ├── libp2p/     # libp2p integration
│   │   ├── encryption/ # End-to-end encryption
│   │   ├── message/    # Secure message exchange
│   │   └── discovery/  # Peer discovery and management
│   └── cli/            # Command-line interface
└── tests/              # Test suite
    ├── crypto/         # Cryptography tests
    ├── network/        # Network tests
    └── integration/    # Integration tests
```

## Setup Instructions

### Prerequisites

- Rust 1.60+ with Cargo
- Go 1.18+
- C compiler (for certain dependencies)

### Building from Source

1. Clone the repository:
   ```
   git clone https://github.com/qasa/qasa.git
   cd qasa
   ```

2. Build the cryptography module:
   ```
   cd src/crypto
   cargo build --release
   ```

3. Build the network module:
   ```
   cd src/network
   go build
   ```

4. Build the CLI:
   ```
   cd src/cli
   cargo build --release
   ```

## Usage

Basic usage instructions will be added as the project develops.

## Security Considerations

This project is in development and has not undergone security audits. Do not use it for sensitive communications until it has been thoroughly vetted by security professionals.

## Contributing

Contributions are welcome! Please see our contributing guidelines (coming soon) for more information.

## License

[MIT License](LICENSE)

# QaSa Cryptography Module

This module implements post-quantum cryptographic primitives for the QaSa secure messaging application.

## Features

- **CRYSTALS-Kyber**: Quantum-resistant key encapsulation mechanism (KEM)
- **CRYSTALS-Dilithium**: Quantum-resistant digital signature scheme
- **AES-GCM**: Authenticated encryption with associated data
- **Key Management**: Secure storage and handling of cryptographic keys

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

This allows devices to choose the most optimal variant that satisfies their security requirements while staying within memory constraints.

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

For one-off signing or verification operations, streamlined functions are provided that allocate and release resources automatically:

```rust
// Sign a message without maintaining state
let signature = lean_sign(message, &secret_key, DilithiumVariant::Dilithium2)?;

// Verify a signature without maintaining state
let is_valid = lean_verify(message, &signature, &public_key, DilithiumVariant::Dilithium2)?;
```

### Batch Verification

For efficient verification of multiple signatures, a batch verification function is provided:

```rust
// Create a batch of messages, signatures, and public keys to verify
let batch = vec![
    (message1, signature1, public_key1, DilithiumVariant::Dilithium2),
    (message2, signature2, public_key2, DilithiumVariant::Dilithium3),
    // ...
];

// Verify all signatures in a memory-efficient way
let results = lean_verify_batch(&batch)?;
```

This function intelligently groups operations by variant to minimise resource usage and can be significantly more efficient than verifying signatures individually.

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

Batch verification (3 signatures) shows significant efficiency gains compared to individual verifications.

## Usage

See the examples directory for detailed usage examples:

- `quantum_signatures.rs`: Example of using Dilithium for digital signatures
- `quantum_safe_chat.rs`: Example of a complete secure messaging protocol 