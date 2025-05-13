# QaSa Cryptography Module

This module implements post-quantum cryptographic primitives for the QaSa secure chat application, with a focus on providing quantum-resistant security.

## Module Structure

The cryptography module is organised into the following sub-modules:

- **kyber**: CRYSTALS-Kyber implementation for quantum-resistant key encapsulation
  - `impl_kyber.rs`: Core implementation of the Kyber algorithm

- **dilithium**: CRYSTALS-Dilithium implementation for quantum-resistant digital signatures
  - `impl_dilithium.rs`: Core implementation of the Dilithium algorithm
  - `optimizations.rs`: Performance optimisations for resource-constrained environments

- **aes**: AES-GCM implementation for symmetric encryption
  - `impl_aes.rs`: Core implementation of AES-GCM encryption/decryption

- **key_management**: Key management system for storing and loading keys
  - `storage.rs`: Functions for securely storing and loading keys
  - `rotation.rs`: Key rotation mechanisms to maintain security
  - `password.rs`: Password-based key derivation and verification

- **error.rs**: Common error types for the cryptography module
- **utils.rs**: Utilities for cryptographic operations

## Examples

The `examples` directory contains example usage of the cryptography primitives:

- `quantum_safe_chat.rs`: A simple end-to-end example of the secure chat protocol
- `quantum_signatures.rs`: Example of using Dilithium for digital signatures
- `optimized_signatures.rs`: Example of using optimised Dilithium implementations

## Benchmarks

The `benches` directory contains performance benchmarks for cryptographic operations.

## Development

When implementing new cryptographic functionality, please follow these guidelines:

1. Place implementation code in the appropriate module directory
2. Add public API functions to the module's `mod.rs` file
3. Document all public functions with doc comments
4. Write comprehensive unit tests
5. Add benchmarks for performance-critical operations
6. Create example code demonstrating the functionality 