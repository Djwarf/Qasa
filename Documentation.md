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
  - [Hardware Security Module (HSM) Integration](#hardware-security-module-hsm-integration)
  - [WebAssembly Support](#webassembly-support)
  - [Python Bindings](#python-bindings)
  - [Formal Verification](#formal-verification)
- [Security](#security)
  - [Threat Model](#threat-model)
  - [Security Features](#security-features)
  - [Best Practices](#best-practices)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Quantum-Resistant Encryption** - Uses NIST-selected post-quantum algorithms CRYSTALS-Kyber, CRYSTALS-Dilithium, and SPHINCS+
- **CRYSTALS-Kyber** - Quantum-resistant key encapsulation mechanism (KEM)
- **CRYSTALS-Dilithium** - Quantum-resistant digital signature scheme
- **SPHINCS+** - Hash-based stateless signature scheme for signature diversity
- **AES-GCM** - Authenticated encryption with associated data
- **Key Management** - Secure storage and handling of cryptographic keys
- **Optimisations** - Special optimisations for resource-constrained environments
- **HSM Integration** - Hardware Security Module support via PKCS#11
- **WebAssembly Support** - Browser and Node.js compatibility
- **Python Bindings** - Easy integration with Python applications
- **Formal Verification** - Mathematical verification of security properties

## Getting Started

### Prerequisites

- Rust 1.60 or later
- A C compiler (GCC or Clang)

### Installation

1. Clone the repository
   ```bash
   git clone https://github.com/Djwarf/Qasa.git
   cd Qasa
   ```

2. Build the cryptography module
   ```bash
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

### Running Examples

To explore the cryptographic functionality, run the provided examples:

```bash
cargo run --example secure_communication
cargo run --example quantum_signatures
cargo run --example hsm_operations
cargo run --example wasm_crypto --features wasm
```

This will demonstrate the available cryptographic algorithms and their usage.

### Key Management

The crypto module provides secure key generation, storage, and management for all supported algorithms.

## Architecture

QaSa focuses on providing a robust cryptography module:

**Crypto Module (Rust)** - Implements the post-quantum cryptographic algorithms
- CRYSTALS-Kyber for key encapsulation
- CRYSTALS-Dilithium for digital signatures
- SPHINCS+ for hash-based signatures
- AES-GCM for symmetric encryption
- Secure key management system
- HSM integration via PKCS#11
- WebAssembly support with optimizations
- Python bindings using PyO3
- Formal verification tools

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

#### SPHINCS+
SPHINCS+ is a stateless hash-based signature scheme providing an alternative signature approach not based on lattices.

SPHINCS+ offers multiple variants with different security/performance tradeoffs:
- **SPHINCS+-128f** - NIST Level 1 security, optimized for speed
- **SPHINCS+-128s** - NIST Level 1 security, optimized for signature size
- **SPHINCS+-192f** - NIST Level 3 security, optimized for speed
- **SPHINCS+-192s** - NIST Level 3 security, optimized for signature size
- **SPHINCS+-256f** - NIST Level 5 security, optimized for speed
- **SPHINCS+-256s** - NIST Level 5 security, optimized for signature size

#### AES-GCM
AES-GCM is used for authenticated symmetric encryption, providing both confidentiality and integrity.

#### Key Management
The key management system provides:
- Secure storage of cryptographic keys
- Key rotation policies
- Backup and recovery mechanisms
- Memory protection for sensitive key material
- HSM integration for enhanced security

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

#### Digital Signatures (SPHINCS+)

```rust
// Generate a new SPHINCS+ key pair
let key_pair = SphincsKeyPair::generate(SphincsVariant::Sphincs192f)?;

// Sign a message
let signature = key_pair.sign(message.as_bytes())?;

// Verify a signature
let is_valid = key_pair.verify(message.as_bytes(), &signature)?;

// Use compressed signatures for reduced size
let compressed = key_pair.sign_compressed(message.as_bytes(), CompressionLevel::Medium)?;
let is_valid = key_pair.verify_compressed(message.as_bytes(), &compressed)?;
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

#### SPHINCS+

| Operation | SPHINCS+-128f | SPHINCS+-128s | SPHINCS+-256f | SPHINCS+-256s |
|-----------|---------------|---------------|---------------|---------------|
| Key Generation | 0.42 ms | 0.38 ms | 0.65 ms | 0.59 ms |
| Signing | 3.50 ms | 12.80 ms | 14.50 ms | 85.30 ms |
| Verification | 0.60 ms | 1.80 ms | 2.10 ms | 6.20 ms |

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

### Hardware Security Module (HSM) Integration

QaSa provides integration with Hardware Security Modules (HSMs) for enhanced key security.

#### HSM Provider Types

```rust
pub enum HsmProvider {
    SoftHsm,    // SoftHSM implementation (for testing)
    Pkcs11,     // Standard PKCS#11 interface
    CloudHsm,   // AWS CloudHSM
    Custom(String), // Custom HSM provider
}
```

#### HSM Configuration

```rust
// Configure HSM connection
let config = HsmConfig {
    library_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
    slot_id: Some(0),
    token_label: Some("qasa".to_string()),
    user_pin: Some(SecureBytes::from(b"1234".to_vec())),
    provider_config: HashMap::new(),
};
```

#### Key Operations with HSM

```rust
// Connect to HSM
let hsm = connect_hsm(HsmProvider::Pkcs11, config.clone())?;

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

// Get public key for verification
let public_key = get_public_key_from_hsm(
    HsmProvider::Pkcs11,
    config.clone(),
    &key_handle
)?;

// Verify signature
let is_valid = verify_signature(
    message,
    &signature,
    &public_key,
    SignatureAlgorithm::Dilithium(DilithiumVariant::Dilithium3)
)?;
```

#### HSM Performance

Performance benchmarks for HSM operations (using SoftHSM):

| Operation | Dilithium2 | Dilithium3 | Dilithium5 |
|-----------|------------|------------|------------|
| Key Generation | 2.15 ms | 3.45 ms | 5.12 ms |
| Signing | 4.87 ms | 7.23 ms | 9.89 ms |
| Verification | 1.12 ms | 1.98 ms | 2.87 ms |

### WebAssembly Support

QaSa provides WebAssembly (WASM) support for browser and Node.js environments.

#### WASM Configuration

```rust
// Configure WASM-specific options
let wasm_config = WasmConfig {
    use_simd: true,
    memory_limit: 16 * 1024 * 1024, // 16MB
    enable_threading: false,
};

// Initialize WASM environment
init_wasm(Some(wasm_config))?;
```

#### WASM-Optimized Operations

```rust
// Use WASM-optimized implementations
let key_pair = KyberKeyPair::generate_optimized(
    KyberVariant::Kyber768,
    OptimizationTarget::Wasm
)?;

// WASM-specific memory handling
let secure_buffer = WasmSecureBuffer::new(32)?;
```

#### JavaScript/TypeScript API

```javascript
// Import the WASM module
import * as qasa from 'qasa-wasm';

// Initialize the module
await qasa.init();

// Generate a key pair
const keyPair = await qasa.kyber.generateKeyPair('kyber768');

// Encapsulate a shared secret
const { ciphertext, sharedSecret } = await qasa.kyber.encapsulate(keyPair.publicKey);

// Decapsulate the shared secret
const decapsulated = await qasa.kyber.decapsulate(ciphertext, keyPair.secretKey);

// Sign a message
const message = new TextEncoder().encode('Hello, quantum-safe world!');
const signature = await qasa.dilithium.sign(message, dilithiumKeyPair.secretKey);

// Verify a signature
const isValid = await qasa.dilithium.verify(message, signature, dilithiumKeyPair.publicKey);
```

#### WASM Performance

Performance benchmarks for WebAssembly operations (Chrome 90+):

| Operation | Kyber768 | Dilithium3 |
|-----------|----------|------------|
| Key Generation | 1.23 ms | 5.67 ms |
| Encapsulation/Signing | 1.45 ms | 12.34 ms |
| Decapsulation/Verification | 1.56 ms | 3.78 ms |

### Python Bindings

QaSa provides Python bindings for easy integration with Python applications.

#### Python Installation

```bash
pip install qasa
```

#### Python API

```python
# Import the QaSa Python module
import qasa

# Initialize the module
qasa.init()

# Key generation
public_key, secret_key = qasa.kyber_keygen(768)  # Kyber-768
ciphertext, shared_secret = qasa.kyber_encapsulate(768, public_key)
decapsulated = qasa.kyber_decapsulate(768, secret_key, ciphertext)

# Signatures
public_key, secret_key = qasa.dilithium_keygen(3)  # Dilithium-3
signature = qasa.dilithium_sign(3, secret_key, b"Hello, quantum-safe world!")
is_valid = qasa.dilithium_verify(3, public_key, b"Hello, quantum-safe world!", signature)

# Encryption
ciphertext, nonce = qasa.aes_encrypt(plaintext, key, associated_data)
decrypted = qasa.aes_decrypt(ciphertext, key, nonce, associated_data)

# Key management
key_id = qasa.store_key("my-key", public_key, secret_key)
pub, sec = qasa.load_key("my-key")
```

#### Python Performance

Performance benchmarks for Python bindings:

| Operation | Kyber768 | Dilithium3 |
|-----------|----------|------------|
| Key Generation | 0.34 ms | 2.15 ms |
| Encapsulation/Signing | 0.38 ms | 5.12 ms |
| Decapsulation/Verification | 0.41 ms | 1.58 ms |

### Formal Verification

QaSa includes formal verification tools to verify security properties of the cryptographic implementations.

#### Verification Properties

```rust
pub enum VerificationProperty {
    ConstantTime,           // Constant-time implementation
    AlgorithmCorrectness,   // Mathematical correctness
    MemorySafety,           // Memory safety properties
    SideChannelResistance,  // Side-channel attack resistance
    ProtocolSecurity,       // Security of the protocol
}
```

#### Verifying Properties

```rust
// Create a formal verifier
let verifier = FormalVerifier::default();

// Verify Kyber implementation
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

// Generate a comprehensive verification report
let report = generate_verification_report(
    "Kyber768",
    &[
        VerificationProperty::ConstantTime,
        VerificationProperty::AlgorithmCorrectness,
        VerificationProperty::SideChannelResistance
    ],
    None
)?;

// Log or display the report
println!("Verification Report: {}", report.summary());
for finding in &report.findings {
    println!("- {}: {}", finding.property, finding.result);
}
```

#### Verification Coverage

Current formal verification coverage:

| Algorithm | Constant-Time | Correctness | Side-Channel | Protocol Security |
|-----------|---------------|-------------|--------------|-------------------|
| Kyber512  | 95% | 90% | 85% | 80% |
| Kyber768  | 95% | 90% | 85% | 80% |
| Kyber1024 | 95% | 90% | 85% | 80% |
| Dilithium2 | 90% | 85% | 80% | 75% |
| Dilithium3 | 90% | 85% | 80% | 75% |
| Dilithium5 | 90% | 85% | 80% | 75% |
| SPHINCS+-192f | 85% | 80% | 75% | 70% |
| AES-GCM | 98% | 95% | 90% | 85% |

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

5. **Web/Browser-Based Adversaries**
   - May inspect WebAssembly memory
   - May intercept data passed between JavaScript and WASM
   - May use browser developer tools to analyze memory

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
- **HSM Integration**: Support for storing and using keys in Hardware Security Modules

#### Memory Security

The module implements secure memory handling to protect sensitive data:

- **Zeroization**: All sensitive buffers are zeroed when no longer needed
- **Secure Containers**: Special container types for sensitive data
- **Scope Guards**: Ensures data is zeroized even if a function returns early or panics
- **WebAssembly Protection**: Special memory handling for WASM environments

#### Formal Verification

The module includes formal verification tools to mathematically prove security properties:

- **Constant-Time Operations**: Verification that cryptographic operations don't leak timing information
- **Algorithm Correctness**: Mathematical proofs of cryptographic algorithm correctness
- **Side-Channel Resistance**: Verification of resistance against various side-channel attacks
- **Protocol Security**: Analysis of cryptographic protocol security properties

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

3. **Use HSMs for critical keys when available**
   ```rust
   // Generate key in HSM instead of in memory
   let key_handle = generate_key_in_hsm(
       HsmProvider::Pkcs11,
       config,
       HsmKeyType::Dilithium(DilithiumVariant::Dilithium3),
       attributes
   )?;
   
   // Use the key without extracting it from the HSM
   let signature = sign_with_hsm(
       HsmProvider::Pkcs11,
       config,
       &key_handle,
       message,
       HsmMechanism::Dilithium(DilithiumVariant::Dilithium3)
   )?;
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

3. **Verify formal security properties in critical applications**
   ```rust
   // Verify that the implementation has the required security properties
   let verifier = FormalVerifier::default();
   let result = verifier.verify_kyber(
       KyberVariant::Kyber768,
       VerificationProperty::ConstantTime
   )?;
   
   if !result.verified {
       return Err(SecurityError::VerificationFailed(result.details));
   }
   ```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The NIST Post-Quantum Cryptography project
- The Open Quantum Safe project
- The CRYSTALS team for Kyber and Dilithium algorithms 