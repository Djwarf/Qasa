# Getting Started with QaSa

This guide will help you get started with the QaSa quantum-safe chat application.

## Prerequisites

Before you begin, ensure you have the following installed:

- Rust 1.60+ with Cargo
- Go 1.18+
- Git
- A C compiler (for building native dependencies)
- CMake and Ninja (for building liboqs)

## Building from Source

### 1. Clone the Repository

```bash
git clone https://github.com/qasa/qasa.git
cd qasa
```

### 2. Build the Cryptography Module

```bash
cd src/crypto
cargo build --release
```

### 3. Build the Network Module

```bash
cd ../network
go mod tidy
go build
```

### 4. Build the CLI

```bash
cd ../cli
cargo build --release
```

## Running QaSa

### Starting a Node

```bash
./target/release/qasa-cli node start
```

### Connecting to a Peer

```bash
./target/release/qasa-cli connect --peer <peer-address>
```

### Sending Messages

```bash
./target/release/qasa-cli send --peer <peer-id> --message "Hello, quantum-safe world!"
```

## Key Management

### Generating New Keys

```bash
./target/release/qasa-cli keys generate
```

### Listing Your Keys

```bash
./target/release/qasa-cli keys list
```

### Backing Up Keys

```bash
./target/release/qasa-cli keys backup --output my-keys-backup.enc
```

### Importing Keys

```bash
./target/release/qasa-cli keys import --input my-keys-backup.enc
```

## Configuration

QaSa uses a configuration file located at `~/.config/qasa/config.json`. You can edit this file to change various settings:

- Network listening addresses
- Bootstrap nodes
- Cryptographic algorithm preferences
- Log levels

## Next Steps

- Read the [Cryptography Guide](./cryptography.md) to learn more about the post-quantum algorithms used in QaSa
- Check out the [Network Architecture](./network.md) to understand how QaSa's peer-to-peer system works
- Learn about [Security Best Practices](./security.md) when using QaSa

## Getting Help

If you encounter issues:

1. Check the [Troubleshooting Guide](./troubleshooting.md)
2. Search for similar issues on our GitHub repository
3. Ask for help in our community channels

## Contributing

We welcome contributions! See the [Contributing Guide](../CONTRIBUTING.md) to learn how you can help improve QaSa. 