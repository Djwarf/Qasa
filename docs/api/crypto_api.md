# QaSa Cryptography API

This document provides an overview of the QaSa cryptography module API.

## Module Overview

The cryptography module provides quantum-resistant cryptographic primitives for:

- Key encapsulation (using CRYSTALS-Kyber)
- Digital signatures (using CRYSTALS-Dilithium and SPHINCS+)
- Symmetric encryption (using AES-GCM)
- Key management
- Hardware Security Module (HSM) integration
- WebAssembly support
- Python bindings
- Formal verification

## Installation

```toml
[dependencies]
qasa = "0.0.5"
```

With optional features:

```toml
[dependencies]
qasa = { version = "0.0.5", features = ["simd", "python", "wasm", "formal-verification"] }
```

## Core Types

### `KyberKeyPair`

Represents a CRYSTALS-Kyber key pair for key encapsulation.

```rust
pub struct KyberKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: KyberVariant,
}
```

### `KyberVariant`

Enum representing different security levels of Kyber.

```rust
pub enum KyberVariant {
    Kyber512,  // NIST security level 1
    Kyber768,  // NIST security level 3, recommended
    Kyber1024, // NIST security level 5
}
```

### `DilithiumKeyPair`

Represents a CRYSTALS-Dilithium key pair for digital signatures.

```rust
pub struct DilithiumKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: DilithiumVariant,
}
```

### `DilithiumVariant`

Enum representing different security levels of Dilithium.

```rust
pub enum DilithiumVariant {
    Dilithium2,  // NIST security level 2
    Dilithium3,  // NIST security level 3, recommended
    Dilithium5,  // NIST security level 5
}
```

### `SphincsKeyPair`

Represents a SPHINCS+ key pair for hash-based digital signatures.

```rust
pub struct SphincsKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: SphincsVariant,
}
```

### `SphincsVariant`

Enum representing different security levels and performance tradeoffs of SPHINCS+.

```rust
pub enum SphincsVariant {
    Sphincs128f,  // NIST security level 1, optimised for speed
    Sphincs128s,  // NIST security level 1, optimised for size
    Sphincs192f,  // NIST security level 3, optimised for speed
    Sphincs192s,  // NIST security level 3, optimised for size
    Sphincs256f,  // NIST security level 5, optimised for speed
    Sphincs256s,  // NIST security level 5, optimised for size
}
```

## Key Encapsulation (Kyber)

### Generating a Key Pair

```rust
// Generate a new Kyber key pair
let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768)?;
```

### Encapsulating a Shared Secret

```rust
// Encapsulate a shared secret using a public key
let (ciphertext, shared_secret) = key_pair.public_key()
    .encapsulate()?;
```

### Decapsulating a Shared Secret

```rust
// Decapsulate a shared secret using a ciphertext
let shared_secret = key_pair
    .decapsulate(&ciphertext)?;
```

## Digital Signatures (Dilithium)

### Generating a Key Pair

```rust
// Generate a new Dilithium key pair
let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3)?;
```

### Signing a Message

```rust
// Sign a message
let signature = key_pair.sign(message)?;
```

### Verifying a Signature

```rust
// Verify a signature
let is_valid = key_pair.public_key()
    .verify(message, &signature)?;
```

## Digital Signatures (SPHINCS+)

### Generating a Key Pair

```rust
// Generate a new SPHINCS+ key pair
let key_pair = SphincsKeyPair::generate(SphincsVariant::Sphincs192f)?;
```

### Signing a Message

```rust
// Sign a message
let signature = key_pair.sign(message)?;

// Sign with compression for reduced size
let compressed = key_pair.sign_compressed(message, CompressionLevel::Medium)?;
```

### Verifying a Signature

```rust
// Verify a standard signature
let is_valid = key_pair.public_key()
    .verify(message, &signature)?;
    
// Verify a compressed signature
let is_valid = key_pair.public_key()
    .verify_compressed(message, &compressed)?;
```

## Symmetric Encryption (AES-GCM)

### Encrypting Data

```rust
// Encrypt data using AES-GCM
let (ciphertext, nonce) = aes::encrypt(plaintext, &key, Some(associated_data))?;
```

### Decrypting Data

```rust
// Decrypt data using AES-GCM
let plaintext = aes::decrypt(&ciphertext, &key, &nonce, Some(associated_data))?;
```

## Key Management

### Storing Keys

```rust
// Store a key with password protection
key_management::store_key("my-key", &key_pair, "password")?;
```

### Loading Keys

```rust
// Load a key with password
let key_pair = key_management::load_key("my-key", "password")?;
```

### Rotating Keys

```rust
// Rotate a key
let new_key_pair = key_management::rotate_key("my-key", "password")?;
```

## Hardware Security Module (HSM) Integration

QaSa provides integration with Hardware Security Modules (HSMs) for enhanced key security.

### HSM Provider Types

```rust
pub enum HsmProvider {
    SoftHsm,    // SoftHSM implementation (for testing)
    Pkcs11,     // Standard PKCS#11 interface
    CloudHsm,   // AWS CloudHSM
    Custom(String), // Custom HSM provider
}
```

### HSM Configuration

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

### Connecting to HSM

```rust
// Connect to an HSM
let hsm = connect_hsm(HsmProvider::SoftHsm, config)?;
```

### Key Generation in HSM

```rust
// Define key attributes
let attributes = HsmKeyAttributes {
    label: "my-dilithium-key".to_string(),
    id: vec![1, 2, 3, 4],
    extractable: false,
    sensitive: true,
    allowed_operations: vec![HsmOperation::Sign, HsmOperation::Verify],
    provider_attributes: HashMap::new(),
};

// Generate key in HSM
let key_handle = generate_key_in_hsm(
    HsmProvider::SoftHsm,
    config.clone(),
    HsmKeyType::Dilithium(DilithiumVariant::Dilithium3),
    attributes
)?;
```

### Cryptographic Operations with HSM

```rust
// Sign using HSM
let signature = sign_with_hsm(
    HsmProvider::SoftHsm,
    config.clone(),
    &key_handle,
    message,
    HsmMechanism::Dilithium(DilithiumVariant::Dilithium3)
)?;

// Verify using HSM
let is_valid = verify_with_hsm(
    HsmProvider::SoftHsm,
    config.clone(),
    &key_handle,
    message,
    &signature,
    HsmMechanism::Dilithium(DilithiumVariant::Dilithium3)
)?;
```

## WebAssembly Support

QaSa provides WebAssembly (WASM) support for browser and Node.js environments.

### WASM Configuration

```rust
// Enable WASM support in Cargo.toml
// qasa = { version = "0.0.5", features = ["wasm"] }

// Configure WASM-specific options
let wasm_config = WasmConfig {
    use_simd: true,
    memory_limit: 16 * 1024 * 1024, // 16MB
    enable_threading: false,
};

// Initialize WASM environment
init_wasm(Some(wasm_config))?;
```

### WASM-Optimized Operations

```rust
// Use WASM-optimized implementations
let key_pair = KyberKeyPair::generate_optimized(
    KyberVariant::Kyber768,
    OptimizationTarget::Wasm
)?;

// WASM-specific memory handling
let secure_buffer = WasmSecureBuffer::new(32)?;
```

## Python Bindings

QaSa provides Python bindings for easy integration with Python applications.

### Python API

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
key_id = qasa.store_key("my-key", public_key, secret_key, "password")
pub, sec = qasa.load_key("my-key", "password")
```

## Formal Verification

QaSa includes formal verification tools to verify security properties of the cryptographic implementations.

### Verification Properties

```rust
pub enum VerificationProperty {
    ConstantTime,           // Constant-time implementation
    AlgorithmCorrectness,   // Mathematical correctness
    MemorySafety,           // Memory safety properties
    SideChannelResistance,  // Side-channel attack resistance
    ProtocolSecurity,       // Security of the protocol
}
```

### Verifying Properties

```rust
// Create a formal verifier
let verifier = FormalVerifier::default();

// Verify Kyber implementation
let result = verifier.verify_kyber(
    KyberVariant::Kyber768,
    VerificationProperty::ConstantTime
)?;

// Verify Dilithium implementation
let result = verifier.verify_dilithium(
    DilithiumVariant::Dilithium3,
    VerificationProperty::ConstantTime
)?;

// Generate a comprehensive verification report
let report = generate_verification_report(
    "Kyber768",
    &[
        VerificationProperty::ConstantTime,
        VerificationProperty::AlgorithmCorrectness
    ],
    None
)?;
```

## Error Handling

All functions return a `Result` type with `CryptoError` for error cases:

```rust
pub enum CryptoError {
    OqsError(String),
    KeyGenerationError(String),
    EncapsulationError(String),
    DecapsulationError(String),
    SignatureGenerationError(String),
    SignatureVerificationError(String),
    EncryptionError(String),
    DecryptionError(String),
    SerializationError(String),
    KeyManagementError(String),
    HsmError(String),
    WasmError(String),
    PythonBindingError(String),
    VerificationError(String),
    IoError(std::io::Error),
    InvalidParameterError(String),
    RandomGenerationError(String),
}
```

## Utilities

### Random Bytes Generation

```rust
// Generate random bytes
let random_data = utils::random_bytes(32)?;
```

### Constant-Time Comparison

```rust
// Compare two byte slices in constant time
let is_equal = utils::constant_time_eq(&bytes1, &bytes2);
```

### Secure Memory Zeroing

```rust
// Zero out sensitive data from memory
utils::secure_zero(&mut sensitive_data);
```

## Example: Complete Encryption Flow

```rust
// Generate a Kyber key pair
let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768)?;

// Generate a shared secret
let (ciphertext, shared_secret) = key_pair.encapsulate()?;

// Use the shared secret for AES encryption
let message = b"Hello, quantum-safe world!";
let (encrypted, nonce) = aes::encrypt(message, &shared_secret, b"")?;

// Send the ciphertext and encrypted message to the recipient
// ...

// Recipient decapsulates the shared secret
let shared_secret = recipient_key_pair.decapsulate(&ciphertext)?;

// Recipient decrypts the message
let decrypted = aes::decrypt(&encrypted, &shared_secret, &nonce, b"")?;
```

## Example: HSM-Based Signing

```rust
// Connect to HSM
let hsm = connect_hsm(HsmProvider::Pkcs11, config)?;

// Generate or load key in HSM
let key_handle = generate_key_in_hsm(
    HsmProvider::Pkcs11,
    config.clone(),
    HsmKeyType::Dilithium(DilithiumVariant::Dilithium3),
    attributes
)?;

// Sign message using HSM
let message = b"Sign this with HSM-protected key";
let signature = sign_with_hsm(
    HsmProvider::Pkcs11,
    config.clone(),
    &key_handle,
    message,
    HsmMechanism::Dilithium(DilithiumVariant::Dilithium3)
)?;

// Verify signature
let public_key = get_public_key_from_hsm(
    HsmProvider::Pkcs11,
    config.clone(),
    &key_handle
)?;

let is_valid = verify_signature(
    message,
    &signature,
    &public_key,
    SignatureAlgorithm::Dilithium(DilithiumVariant::Dilithium3)
)?;
```