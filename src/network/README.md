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
The QaSa chat application can be launched using one of the provided scripts:

#### Option 1: Using the full-featured launcher
The full-featured launcher provides advanced configuration options and can install the shared library system-wide (requires sudo):

```bash
./qasa-cli.sh [options]
```

#### Option 2: Using the simple launcher
The simple launcher doesn't require sudo privileges and handles library paths automatically:

```bash
./qasa-run.sh [options]
```

Command-line options for both scripts:
- `--port, -p PORT`: Port to listen on (0 for random port)
- `--config, -c DIR`: Configuration directory (default: ~/.qasa)
- `--no-mdns`: Disable mDNS discovery
- `--dht`: Enable DHT-based peer discovery
- `--auth`: Require peer authentication
- `--no-offline-queue`: Disable offline message queuing
- `--bootstrap, -b NODE`: Add a bootstrap node
- `--connect, -C PEER`: Peer to connect to
- `--help, -h`: Display help information

#### Troubleshooting
If you encounter library dependency issues:

1. Ensure Rust and Go are properly installed
2. Build the Rust library manually:
   ```bash
   cd src/crypto
   cargo build --release
   ```
3. Set the library path before running:
   ```bash
   export LD_LIBRARY_PATH="$(pwd)/target/release:$LD_LIBRARY_PATH"
   cd ../network
   ./qasa-network
   ```

### Using the Command-Line Interface

Once the application is running, you can use the following commands:

#### Messaging
- `send <peer index> <message>`: Send a message to a peer

#### Network Management
- `list` or `peers`: List connected peers
- `connect <address>`: Connect to a peer
- `bootstrap <address>`: Add a bootstrap node
- `key-exchange <peer index>`: Initiate key exchange with a peer

#### Key Management
- `keys list`: List all keys in the key store
- `keys generate <algorithm>`: Generate a new key pair (kyber768 or dilithium3)
- `keys import <file>`: Import a key from a file
- `keys export <peer ID> <algo>`: Export a key to a file
- `keys delete <peer ID> <algo>`: Delete a key from the key store
- `keys info <peer ID> <algo>`: Display information about a key
- `keys rotate <algo>`: Rotate a key pair

#### System
- `status`: Display node status
- `encrypt-test`: Test encryption/decryption
- `help`: Display help information
- `quit` or `exit`: Exit the application

### Example Session

```
# Start the application
./qasa-cli.sh --port 9000

# In the application
> peers
No peers connected.

> keys list
Keys in key store:
• Peer: 12D3KooW... (local node)
  - kyber768 (created: 2023-10-15)
  - dilithium3 (created: 2023-10-15)

> connect /ip4/192.168.1.5/tcp/9001/p2p/12D3KooWB2N4ywn4MWYt...
Connected to peer: /ip4/192.168.1.5/tcp/9001/p2p/12D3KooWB2N4ywn4MWYt...
Peer authenticated: 12D3KooWB2N4...
Metadata exchanged with peer: 12D3KooWB2N4...

> send 0 Hello, this is a secure post-quantum message!
Message sent to peer 0 (12D3KooWB2N4...)

> keys rotate kyber768
Rotating kyber768 key pair for 12D3KooW...
Previous key created: 2023-10-15 10:30:45
Key rotation complete. New kyber768 key generated.

> status
📊 Node Status
Peer ID: 12D3KooW...
Listening Addresses:
  - /ip4/192.168.1.10/tcp/9000/p2p/12D3KooW...
  - /ip4/127.0.0.1/tcp/9000/p2p/12D3KooW...
Connected Peers: 1
Authenticated Peers: 1/1
Queued Messages: 0

> quit
Exiting...
```

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