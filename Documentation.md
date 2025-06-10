# QaSa - Quantum-Safe Cryptography Module

QaSa (Quantum-Safe) is a post-quantum cryptography implementation that provides protection against quantum computer attacks using NIST-selected algorithms.

## Table of Contents
- [Features](#features)
- [Getting Started](#getting-started)
- [Architecture](#architecture)
- [Cryptography Module](#cryptography-module)
  - [Core Components](#core-components)
  - [API Overview](#api-overview)
  - [Performance Metrics](#performance-metrics)
  - [Memory-Efficient Implementations](#memory-efficient-implementations)
- [Security](#security)
  - [Threat Model](#threat-model)
  - [Security Features](#security-features)
  - [Best Practices](#best-practices)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Quantum-Resistant Encryption** - Uses NIST-selected post-quantum algorithms CRYSTALS-Kyber and CRYSTALS-Dilithium
- **CRYSTALS-Kyber** - Quantum-resistant key encapsulation mechanism (KEM)
- **CRYSTALS-Dilithium** - Quantum-resistant digital signature scheme
- **AES-GCM** - Authenticated encryption with associated data
- **Key Management** - Secure storage and handling of cryptographic keys
- **Optimisations** - Special optimisations for resource-constrained environments

## Getting Started

### Prerequisites

- Rust 1.60 or later
- A C compiler (GCC or Clang)

### Installation

1. Clone the repository
   ```bash
   git clone https://github.com/qasa/qasa.git
   cd qasa
   ```

2. Build the cryptography module
   ```bash
   cd src/crypto
   cargo build --release
   ```

3. Test the module
   ```bash
   cargo test
   ```

4. Run benchmarks
   ```bash
   cargo bench
   ```

### Running the Application

Display crypto module information:

```bash
cd src && go run main.go
```

This will display information about the available cryptographic algorithms and documentation locations.

### Key Management

The crypto module provides secure key generation, storage, and management for all supported algorithms.

## Architecture

QaSa focuses on providing a robust cryptography module:

**Crypto Module (Rust)** - Implements the post-quantum cryptographic algorithms
- CRYSTALS-Kyber for key encapsulation
- CRYSTALS-Dilithium for digital signatures
- AES-GCM for symmetric encryption
- Secure key management system

## Cryptography Module

The cryptography module provides quantum-resistant cryptographic primitives for secure communications.

### Core Components

#### CRYSTALS-Kyber
CRYSTALS-Kyber is a key encapsulation mechanism (KEM) based on the hardness of solving the learning-with-errors (LWE) problem over module lattices.

Kyber offers three security levels:
- **Kyber512** - NIST Level 1 security (equivalent to AES-128)
- **Kyber768** - NIST Level 3 security (equivalent to AES-192)
- **Kyber1024** - NIST Level 5 security (equivalent to AES-256)

#### CRYSTALS-Dilithium
CRYSTALS-Dilithium is a digital signature scheme also based on module lattices.

Dilithium offers three security levels:
- **Dilithium2** - NIST Level 2 security
- **Dilithium3** - NIST Level 3 security
- **Dilithium5** - NIST Level 5 security

#### AES-GCM
AES-GCM is used for authenticated symmetric encryption, providing both confidentiality and integrity.

#### Key Management
The key management system provides:
- Secure storage of cryptographic keys
- Key rotation policies
- Backup and recovery mechanisms
- Memory protection for sensitive key material

### API Overview

#### Key Encapsulation (Kyber)

```rust
// Generate a new Kyber key pair
let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768)?;

// Encapsulate a shared secret using a public key
let (ciphertext, shared_secret) = key_pair.encapsulate()?;

// Decapsulate a shared secret using a ciphertext and the secret key
let shared_secret = key_pair.decapsulate(&ciphertext)?;
```

#### Digital Signatures (Dilithium)

```rust
// Generate a new Dilithium key pair
let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)?;

// Sign a message
let signature = key_pair.sign(message.as_bytes())?;

// Verify a signature
let is_valid = key_pair.verify(message.as_bytes(), &signature)?;
```

#### Symmetric Encryption (AES-GCM)

```rust
// Encrypt data using AES-GCM
let (ciphertext, nonce) = aes::encrypt(plaintext, &key, &associated_data)?;

// Decrypt data using AES-GCM
let plaintext = aes::decrypt(&ciphertext, &key, &nonce, &associated_data)?;
```

#### Key Management

```rust
// Store a key with password protection
key_management::store_key("my-key", &key_pair, "password")?;

// Load a key with password
let key_pair = key_management::load_key("my-key", "password")?;

// Rotate a key
let new_key_pair = key_management::rotate_key("my-key", "password")?;
```

### Performance Metrics

Performance benchmarks for the cryptography module on a modern system:

#### CRYSTALS-Kyber

| Operation | Kyber512 | Kyber768 | Kyber1024 |
|-----------|----------|----------|-----------|
| Key Generation | 0.17 ms | 0.31 ms | 0.45 ms |
| Encapsulation | 0.21 ms | 0.36 ms | 0.53 ms |
| Decapsulation | 0.25 ms | 0.39 ms | 0.58 ms |

#### CRYSTALS-Dilithium

| Operation | Dilithium2 | Dilithium3 | Dilithium5 |
|-----------|------------|------------|------------|
| Key Generation | 1.25 ms | 2.09 ms | 3.27 ms |
| Signing | 3.21 ms | 4.98 ms | 7.16 ms |
| Verification | 0.87 ms | 1.52 ms | 2.31 ms |

#### AES-GCM

| Operation | Small (32B) | Medium (1KB) | Large (1MB) |
|-----------|-------------|--------------|-------------|
| Encryption | 2.9 µs | 19.7 µs | 13.8 ms |
| Decryption | 3.1 µs | 20.3 µs | 14.2 ms |

### Memory-Efficient Implementations

The cryptography module includes special optimizations for resource-constrained environments, particularly for the Dilithium signature scheme:

#### Memory-Efficient Variant Selection

```rust
// Select the appropriate variant for a device with limited memory
let variant = DilithiumVariant::for_constrained_environment(
    2, // Minimum security level
    8  // Available memory in KB
);
```

#### Lazy Initialization

```rust
// Create a lean implementation that doesn't initialize resources immediately
let mut lean = LeanDilithium::new(DilithiumVariant::Dilithium2);

// Resources are only allocated when needed
let signature = lean.sign(message, &secret_key)?;

// Resources can be explicitly released when no longer needed
lean.release_resources();
```

#### Streamlined Operations

```rust
// Sign a message without maintaining state
let signature = lean_sign(message, &secret_key, DilithiumVariant::Dilithium2)?;

// Verify a signature without maintaining state
let is_valid = lean_verify(message, &signature, &public_key, DilithiumVariant::Dilithium2)?;
```

#### Batch Verification

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

Optimized implementations maintain performance comparable to standard implementations:

| Operation | Standard Implementation | Optimized Implementation |
|-----------|-------------------------|--------------------------|
| Dilithium2 Sign | ~39.3 µs | ~39.2 µs |
| Dilithium2 Verify | ~14.7 µs | ~14.7 µs |
| Dilithium3 Sign | ~63.5 µs | ~63.2 µs |
| Dilithium3 Verify | ~24.7 µs | ~24.7 µs |
| Dilithium5 Sign | ~76.9 µs | ~78.8 µs |
| Dilithium5 Verify | ~38.7 µs | ~39.2 µs |

Batch verification (3 signatures) shows significant efficiency gains compared to individual verifications.

## Security

### Threat Model

The QaSa cryptography module is designed to resist the following types of adversaries:

1. **Cryptographic Adversaries**
   - May attempt to break the cryptographic algorithms themselves
   - May try to recover keys from cryptographic operations
   - May attempt chosen plaintext/ciphertext attacks

2. **System Adversaries**
   - May have access to persistent storage, but not the running process memory
   - May attempt to access stored keys on disk
   - May attempt to recover deleted keys from disk

3. **Quantum Adversaries**
   - May have access to large-scale quantum computers
   - Can run Shor's algorithm to break traditional public key cryptography
   - Can run Grover's algorithm, effectively halving symmetric key security

4. **Side-Channel Attackers**
   - May attempt timing attacks to extract key information
   - May analyze power consumption or electromagnetic emissions
   - May perform cache-timing and other microarchitectural attacks

### Security Features

#### Post-Quantum Resistance

All cryptographic operations use algorithms designed to resist attacks from quantum computers:

- **Kyber** uses lattice-based cryptography which is believed to be resistant to quantum attacks
- **Dilithium** provides signature security against quantum adversaries
- **AES-256** provides sufficient security margin against Grover's algorithm

#### Authenticated Encryption

All encryption operations use AES-GCM, which provides:

- **Confidentiality**: Messages remain secret from unauthorized parties
- **Integrity**: Any modification to ciphertext will be detected
- **Authentication**: Proof that the message came from a trusted source

#### Key Management

The module includes a comprehensive key management system:

- **Secure Storage**: Keys are stored encrypted with password-derived keys
- **Key Rotation**: Automatic or manual key rotation with configurable policies
- **Key Backup**: Export/import functionality with password protection
- **Key Verification**: Methods to verify key pair validity

#### Memory Security

The module implements secure memory handling to protect sensitive data:

- **Zeroization**: All sensitive buffers are zeroed when no longer needed
- **Secure Containers**: Special container types for sensitive data
- **Scope Guards**: Ensures data is zeroized even if a function returns early or panics

### Best Practices

#### Key Handling

1. **Never store raw keys in persistent storage**
   ```rust
   // WRONG: Storing raw keys
   fs::write("private.key", &keypair.secret_key)?;
   
   // CORRECT: Use the secure storage functions
   let key_id = store_kyber_keypair(&keypair, None, "strong_password")?;
   ```

2. **Use secure memory for sensitive operations**
   ```rust
   // WRONG: Using standard Vec for sensitive data
   let shared_secret = decrypt_key(ciphertext, keypair)?;
   
   // CORRECT: Using SecureBytes for sensitive data
   let shared_secret = SecureBytes::from(decrypt_key(ciphertext, keypair)?);
   ```

#### Authentication and Integrity

1. **Always verify signatures before processing messages**
   ```rust
   // WRONG: Decrypting without verifying
   let plaintext = decrypt_message(&encrypted, &key, &nonce, &keypair)?;
   
   // CORRECT: Verifying and decrypting
   let plaintext = decrypt_and_verify_message(
       &encrypted, &key, &nonce, &signature, &keypair, &sender_key
   )?;
   ```

2. **Use AAD (Associated Authenticated Data) when relevant**
   ```rust
   // Encrypt with AAD to bind contextual data to the encryption
   let (ciphertext, nonce) = aes::encrypt(
       &message, 
       &shared_secret, 
       Some(&conversation_id)
   )?;
   ```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The NIST Post-Quantum Cryptography project
- The Open Quantum Safe project
- The CRYSTALS team for Kyber and Dilithium algorithms 