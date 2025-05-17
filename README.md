# QaSa - Quantum-Safe Secure Chat

QaSa (Quantum-Safe) is a secure end-to-end encrypted chat application that uses post-quantum cryptography to provide protection against quantum computer attacks.

## Features

- **Quantum-Resistant Encryption** - Uses NIST-selected post-quantum algorithms CRYSTALS-Kyber and CRYSTALS-Dilithium
- **End-to-End Encryption** - All messages are encrypted using strong cryptographic algorithms
- **Peer-to-Peer Communication** - Direct communication without central servers
- **Identity Management** - Associate usernames with cryptographic keys
- **Peer Discovery** - Find other users through DHT, mDNS, and custom discovery mechanisms
- **Web Interface** - Modern, responsive UI for easy interaction

## Getting Started

### Prerequisites

- Go 1.18 or later
- Rust 1.60 or later
- A C compiler (GCC or Clang)

### Installation

1. Clone the repository
   ```
   git clone https://github.com/djwarf/Qasa.git
   cd Qasa
   ```

2. Build the crypto module
   ```
   cd src/crypto
   cargo build --release
   ```

3. Build the network module
   ```
   cd ../network
   ./build_crypto.sh
   go build -o qasa-network
   ```

### Running the Application

The easiest way to run QaSa is to use the Web UI:

```
./run_web_ui.sh
```

This will start the application and web interface on port 8080. Open your browser and navigate to:

```
http://localhost:8080
```

To specify a different port:

```
./run_web_ui.sh 9000
```

For advanced usage, you can also run the command-line interface:

```
cd src/network
./qasa-cli.sh
```

## Web Interface

The web interface provides an easy-to-use way to interact with QaSa. It features:

### Contacts Tab
- View and manage your connections
- See online/offline status
- Chat with end-to-end encryption
- Verify encryption status

### Discovery Tab
- Search for peers by username, key ID, or general search
- Filter results by online status, authentication, and encryption
- Sort by network proximity
- Connect and chat directly from the discovery interface

### Profile Management
- Set a username for easier identification
- Associate your profile with a specific key
- Add additional metadata to your profile

### Security Settings
- Configure network settings (mDNS, DHT)
- Set security preferences
- Manage your cryptographic keys

## Architecture

QaSa is built on a modular architecture with two main components:

1. **Crypto Module (Rust)** - Implements the post-quantum cryptographic algorithms
   - CRYSTALS-Kyber for key encapsulation
   - CRYSTALS-Dilithium for digital signatures
   - AES-GCM for symmetric encryption
   - Key management system

2. **Network Module (Go)** - Handles peer-to-peer communication
   - libp2p for P2P networking
   - End-to-end encryption
   - Message exchange protocol
   - Peer discovery and management
   - Web interface

## Security Considerations

QaSa implements post-quantum cryptography to protect against future quantum computer attacks. However, this is a research project and not intended for use in high-security environments without further review.

Key security features:
- Post-quantum key exchange with CRYSTALS-Kyber
- Post-quantum signatures with CRYSTALS-Dilithium
- AES-GCM for message encryption
- Peer authentication

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The NIST Post-Quantum Cryptography project
- The Open Quantum Safe project
- libp2p for the P2P networking libraries

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