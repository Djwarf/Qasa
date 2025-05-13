# QaSa Encryption Module

This module provides quantum-resistant encryption for the QaSa chat application. It uses post-quantum cryptography algorithms to protect messages against attacks from both classical and quantum computers.

### Architecture

The encryption module is divided into two main parts:

1. **Rust Cryptography Library**: Provides high-performance, post-quantum cryptographic primitives
   - CRYSTALS-Kyber for key encapsulation (KEM)
   - CRYSTALS-Dilithium for digital signatures
   - AES-GCM for symmetric encryption

2. **Go Bindings and Integration**: Provides an easy-to-use interface for the Go network module
   - Foreign Function Interface (FFI) to call Rust functions from Go
   - Key management system
   - Session management for optimized performance

### Message Encryption/Decryption Workflow

The message encryption/decryption workflow enables secure communication between peers using quantum-resistant algorithms. The workflow is implemented in the `MessageCrypto` class, which provides the following features:

#### 1. Key Management

The `KeyStore` class is responsible for:
- Generating and storing key pairs for the local node
- Storing public keys for remote peers
- Loading and saving keys securely to disk

#### 2. Direct Encryption

When a message needs to be sent to a peer, the workflow works as follows:

1. The sender retrieves the recipient's public key
2. The sender uses Kyber to encapsulate a shared secret with the recipient's public key
3. The shared secret is used as a key for AES-GCM encryption
4. The ciphertext, along with necessary metadata, is sent to the recipient
5. The recipient decapsulates the shared secret using their private key
6. The recipient uses the shared secret to decrypt the message

#### 3. Session Keys

For performance optimization, the system supports session keys:

1. A session key is established using Kyber and stored in a cache
2. Subsequent messages use the cached session key directly
3. Session keys expire after a certain period (default: 1 hour)
4. New session keys are automatically established when needed

#### 4. Message Authentication

Messages are authenticated using Dilithium signatures:

1. The sender signs the message content with their private Dilithium key
2. The signature is attached to the message
3. The recipient verifies the signature using the sender's public key
4. This ensures the message was not tampered with and genuinely came from the claimed sender

### Usage

1. **Creating the Message Crypto Provider**:
   ```go
   provider, err := encryption.GetCryptoProvider()
   if err != nil {
       // Handle error
   }
   
   messageCrypto, err := encryption.NewMessageCrypto(provider, configDir)
   if err != nil {
       // Handle error
   }
   ```

2. **Encrypting a Message**:
   ```go
   // Encrypt a message for a recipient
   ciphertext, err := messageCrypto.EncryptMessage(plaintext, recipientID)
   if err != nil {
       // Handle error
   }
   ```

3. **Decrypting a Message**:
   ```go
   // Decrypt a message from a sender
   plaintext, err := messageCrypto.DecryptMessage(ciphertext, senderID)
   if err != nil {
       // Handle error
   }
   ```

4. **Creating Key Exchange**:
   ```go
   // Establish a session key with a peer
   sessionKey, err := messageCrypto.EstablishSessionKey(peerID)
   if err != nil {
       // Handle error
   }
   ```

### Security Considerations

1. **Post-Quantum Security**: All cryptographic operations use algorithms believed to be resistant to quantum computer attacks.

2. **Forward Secrecy**: Session keys are rotated regularly to provide forward secrecy.

3. **Message Authentication**: All messages are authenticated with signatures to verify the sender's identity.

4. **Key Storage**: Keys are stored securely on disk with appropriate permissions.

### Implementation Details

The message encryption/decryption workflow is implemented in:
- `message_crypto.go`: Core encryption/decryption functionality
- `key_store.go`: Key management system
- `provider.go`: Interface to the Rust cryptography library

The Go network module integrates this by:
- Using the message workflow in the message protocol
- Handling key exchange during connection establishment
- Providing session management for efficiency

## Overview

The encryption module provides:

1. **FFI Interface** - Low-level bindings to the Rust cryptography library.
2. **Crypto Provider** - Implementation of the CryptoProvider interface using the FFI bindings.
3. **Key Exchange** - A handshake protocol for securely establishing shared secrets.
4. **Message Encryption** - Methods for encrypting and decrypting messages.

## Components

### FFI Interface (`qasa_crypto.h`, `qasa_crypto.go`)

These files provide the glue between Go and Rust. The header file defines the C API exposed by the Rust library, and the Go file provides CGO bindings to call these functions.

### Crypto Provider (`provider.go`, `factory.go`)

- `provider.go` - Implements the `CryptoProvider` interface using the FFI bindings.
- `factory.go` - Provides factory functions to get crypto provider instances.

### Key Exchange (`handshake.go`)

Implements a three-step handshake protocol for key exchange:
1. Initiator sends public key and encapsulated shared secret.
2. Responder processes message, derives shared secret, and sends response.
3. Initiator finalizes handshake with a confirmation message.

### Interface (`interface.go`)

Defines the public interfaces for the encryption module:
- `CryptoProvider` - For cryptographic operations
- `KeyPair` - Represents a cryptographic key pair
- `Message` - Represents an encrypted message
- `SessionKey` - Represents a temporary session key

## Post-Quantum Security

This module uses quantum-resistant algorithms from the NIST Post-Quantum Cryptography standardization process:

- **CRYSTALS-Kyber** for key encapsulation mechanism (KEM) - Ensures shared secrets remain secure against quantum attacks.
- **CRYSTALS-Dilithium** for digital signatures - Ensures message authenticity remains secure against quantum attacks.
- **AES-GCM** for symmetric encryption - Used with keys established via quantum-resistant KEMs.

## Building

The Rust cryptography library must be built before using this module. Run the `build_crypto.sh` script in the network directory:

```bash
cd src/network
./build_crypto.sh
```

This script will:
1. Build the Rust library in release mode
2. Copy the header file to the right location
3. Create symlinks for the shared library

## Usage Example

```go
// Get the crypto provider
provider, err := encryption.GetCryptoProvider()
if err != nil {
    log.Fatalf("Failed to get crypto provider: %v", err)
}

// Generate keys
keyPair, err := provider.GenerateKeyPair("kyber768")
if err != nil {
    log.Fatalf("Failed to generate key pair: %v", err)
}

// Encrypt data
ciphertext, err := provider.Encrypt(message, recipientPublicKey)
if err != nil {
    log.Fatalf("Failed to encrypt: %v", err)
}

// Decrypt data
plaintext, err := provider.Decrypt(ciphertext, privateKey)
if err != nil {
    log.Fatalf("Failed to decrypt: %v", err)
}

// Sign data
signature, err := provider.Sign(message, privateKey)
if err != nil {
    log.Fatalf("Failed to sign: %v", err)
}

// Verify signature
valid, err := provider.Verify(message, signature, publicKey)
if err != nil {
    log.Fatalf("Failed to verify: %v", err)
}
```

## Testing

A test program is provided in the `examples` directory to verify that the FFI implementation is working correctly:

```bash
cd src/network
go run examples/crypto_test.go
``` 