# QaSa Network Module

This module provides secure, decentralized networking for the QaSa post-quantum chat application. It uses quantum-resistant cryptography to protect communications against both classical and quantum computer attacks.

## Features

- **Peer-to-Peer Communication**: Built on libp2p for robust, decentralized networking
- **End-to-End Encryption**: All messages are encrypted using post-quantum cryptography
- **Perfect Forward Secrecy**: Session keys are rotated regularly to ensure security even if keys are compromised
- **Message Authentication**: Digital signatures verify the authenticity of messages
- **Offline Message Queuing**: Messages are queued for offline recipients and delivered when they reconnect
- **DHT-Based Peer Discovery**: Peers can discover each other through a distributed hash table
- **Bootstrap Nodes**: Configurable bootstrap nodes help with initial network connection

## Architecture

The network module is divided into several components:

### 1. Core Network (libp2p)
Builds on libp2p to provide peer-to-peer connectivity, including:
- Connection management
- NAT traversal
- Peer authentication
- Metadata exchange

### 2. Message Protocol
Handles message exchange between peers, including:
- Message formatting
- Delivery guarantees
- Acknowledgment system
- Offline message queuing

### 3. Encryption Module
Provides quantum-resistant security, including:
- CRYSTALS-Kyber for key encapsulation
- CRYSTALS-Dilithium for digital signatures
- AES-GCM for symmetric encryption
- Session key management with perfect forward secrecy

### 4. Discovery
Enables peers to find each other, including:
- DHT-based peer discovery
- Bootstrap node configuration
- Peer reputation system
- Connection management

## Usage

### Building
The network module requires both Go and Rust to build:

```bash
# Build the Rust cryptography library
cd src/crypto
cargo build --release

# Build the Go network module
cd src/network
./build_crypto.sh
go build -o qasa-network
```

### Running
Run the network module with:

```bash
./qasa-network
```

Command-line options:
- `--address`: Local address to listen on (default: 0.0.0.0)
- `--port`: Port to listen on (default: 9000)
- `--bootstrap`: Bootstrap node addresses (comma-separated)
- `--config`: Configuration file path (default: .qasa/config.json)
- `--no-offline-queue`: Disable offline message queuing

## Implementation Details

### Message Encryption/Decryption Workflow

The message encryption/decryption workflow provides end-to-end encryption with perfect forward secrecy:

1. **Session Key Establishment**:
   - Peers establish session keys using Kyber key encapsulation
   - Session keys have a limited lifetime (default: 1 hour)
   - Keys are rotated periodically (default: every 5 minutes)

2. **Message Encryption**:
   - Messages are signed using Dilithium
   - Messages are encrypted using the current session key with AES-GCM
   - If no session key exists, messages are encrypted directly using Kyber

3. **Message Decryption**:
   - Messages are decrypted using the appropriate session key
   - Message signatures are verified using the sender's public key

### Chat Protocol

The chat protocol handles message exchange:

1. **Connection Management**:
   - Peers establish connections using libp2p
   - Streams are created for each peer connection
   - The protocol handles disconnects and reconnects

2. **Message Delivery**:
   - Messages include unique IDs, sender info, and timestamps
   - Recipients acknowledge messages to confirm delivery
   - Failed deliveries are retried automatically

3. **Offline Messaging**:
   - Messages for offline peers are stored locally
   - Queued messages are delivered when peers reconnect
   - The queue is maintained persistently on disk

## Security Considerations

1. **Post-Quantum Security**: All cryptographic operations use algorithms believed to be resistant to quantum computer attacks.

2. **Perfect Forward Secrecy**: Session keys are rotated regularly, limiting the impact of key compromise.

3. **Message Authentication**: All messages are authenticated with signatures to verify the sender's identity.

4. **Key Storage**: Keys are stored securely on disk with appropriate permissions.

## Future Development

1. **Group Chat**: Add support for secure group messaging with multicast encryption.

2. **File Transfer**: Implement secure file transfers using the same encryption mechanisms.

3. **Improved Discovery**: Enhance peer discovery with additional methods like mDNS for local network discovery.

4. **Mobile Support**: Optimize for mobile platforms with battery and bandwidth considerations. 