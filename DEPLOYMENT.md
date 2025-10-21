# QaSa Cryptography Module - Build and Deployment Guide

This document provides comprehensive instructions for building, testing, and deploying the QaSa post-quantum cryptography module.

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Architecture**: x86_64, ARM64 (depending on target platform)
- **Memory**: Minimum 4GB RAM for building
- **Disk Space**: Minimum 2GB free space

### Development Tools

- **Rust**: Version 1.60 or later
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source ~/.cargo/env
  ```

- **C Compiler**: GCC or Clang
  ```bash
  # On Ubuntu/Debian
  sudo apt-get install build-essential
  
  # On macOS
  xcode-select --install
  
  # On CentOS/RHEL
  sudo yum groupinstall "Development Tools"
  ```

- **Git**: For version control
  ```bash
  # On Ubuntu/Debian
  sudo apt-get install git
  
  # On macOS
  brew install git
  ```

## Building the Crypto Module

### Quick Build

Navigate to the crypto module directory and build:

```bash
cargo build --release
```

### Development Build

For development with debug symbols:

```bash
cargo build
```

### Build Configuration

The crypto module supports various build configurations:

#### Feature Flags

- `default`: Standard features including all algorithms
- `kyber`: CRYSTALS-Kyber KEM only
- `dilithium`: CRYSTALS-Dilithium signatures only
- `sphincsplus`: SPHINCS+ signatures only
- `aes`: AES-GCM symmetric encryption only
- `optimized`: Memory and performance optimizations
- `lean`: Minimal footprint for constrained environments

Example build with specific features:

```bash
cargo build --release --no-default-features --features "kyber,dilithium,sphincsplus,optimized"
```

#### Target Platforms

Build for specific platforms:

```bash
# For ARM64
cargo build --release --target aarch64-unknown-linux-gnu

# For WebAssembly
cargo build --release --target wasm32-unknown-unknown

# For Windows
cargo build --release --target x86_64-pc-windows-gnu
```

## Testing

### Unit Tests

Run the complete test suite:

```bash
cargo test
```

Run tests with output:

```bash
cargo test -- --nocapture
```

Run specific test modules:

```bash
cargo test kyber::tests
cargo test dilithium::tests
cargo test sphincsplus::tests
cargo test key_management::tests
```

### Integration Tests

Run integration tests:

```bash
cargo test --test integration
```

### Security Tests

Run security-focused tests:

```bash
cargo test security
cargo test constant_time
```

## Benchmarking

### Performance Benchmarks

Run all benchmarks:

```bash
cargo bench
```

Run specific algorithm benchmarks:

```bash
cargo bench kyber
cargo bench dilithium
cargo bench sphincsplus
cargo bench aes
```

### Memory Usage Analysis

Analyze memory usage with Valgrind (Linux only):

```bash
cargo build --release
valgrind --tool=massif target/release/qasa
```

## Documentation

### Generate Documentation

Generate API documentation:

```bash
cargo doc --open
```

Generate documentation with private items:

```bash
cargo doc --document-private-items --open
```

## Installation

### System-wide Installation

Install the crypto library system-wide:

```bash
cargo install --path .
```

### Library Installation

To use as a library dependency, add to `Cargo.toml`:

```toml
[dependencies]
qasa = { path = "." }
```

## Configuration

### Environment Variables

Configure runtime behavior:

```bash
# Set log level
export RUST_LOG=qasa=debug

# Set memory allocation strategy
export QASA_MEMORY_STRATEGY=secure

# Set random number generation source
export QASA_RNG_SOURCE=system
```

### Configuration Files

The crypto module supports configuration via `crypto.toml`:

```toml
[security]
# Use secure memory allocation
secure_memory = true

# Enable constant-time operations
constant_time = true

# Memory zeroization policy
zeroize_on_drop = true

[algorithms]
# Default Kyber variant
kyber_variant = "Kyber768"

# Default Dilithium variant  
dilithium_variant = "Dilithium3"

# Default SPHINCS+ variant
sphincsplus_variant = "Sphincs192f"

# AES key size
aes_key_size = 256

[performance]
# Enable SIMD optimizations
simd = true

# Use hardware acceleration when available
hardware_accel = true

[memory]
# Memory usage mode: "standard", "optimized", "minimal"
usage_mode = "optimized"

# Maximum memory per operation (bytes)
max_memory_per_op = 1048576  # 1MB
```

## Security Considerations

### Build Security

- Always use release builds for production: `cargo build --release`
- Verify checksums of dependencies: `cargo audit`
- Use reproducible builds when possible
- Enable stack protection and ASLR in the target environment

### Runtime Security

- Store cryptographic keys securely using the key management system
- Use secure memory allocation when available
- Enable memory zeroization for sensitive data
- Monitor for side-channel attacks in production environments

### Key Management

The crypto module includes secure key storage:

```bash
# Create a new key store
mkdir -p ~/.qasa/keys
chmod 700 ~/.qasa/keys

# Generate initial keys (done automatically on first run)
```

## Deployment Scenarios

### Embedded Systems

For embedded or resource-constrained environments:

```bash
# Build with minimal features
cargo build --release --no-default-features --features "lean"

# Use size optimization
export CARGO_TARGET_<TARGET>_RUSTFLAGS="-C opt-level=s"
```

### High-Performance Systems

For high-performance requirements:

```bash
# Build with all optimizations
cargo build --release --features "optimized,simd"

# Use native CPU features
export RUSTFLAGS="-C target-cpu=native"
```

### WebAssembly

For web deployment:

```bash
# Install wasm-pack
cargo install wasm-pack

# Build for web
wasm-pack build --target web --out-dir pkg

# Generate TypeScript bindings
wasm-pack build --typescript
```

## Monitoring and Maintenance

### Health Checks

Monitor crypto module health:

```bash
# Check algorithm functionality
qasa --self-test

# Verify key integrity
qasa --verify-keys

# Performance baseline
qasa --benchmark
```

### Updates

Keep the crypto module updated:

```bash
# Update dependencies
cargo update

# Check for security advisories
cargo audit

# Update documentation
cargo doc --no-deps
```

### Backup Procedures

**Important**: Back up cryptographic keys regularly:

```bash
# Backup key directory
tar -czf qasa-keys-backup-$(date +%Y%m%d).tar.gz ~/.qasa/keys/

# Store backup securely (encrypted external storage recommended)
```

## Troubleshooting

### Common Issues

1. **Build Failures**
   ```bash
   # Clean and rebuild
   cargo clean
   cargo build --release
   ```

2. **Missing Dependencies**
   ```bash
   # Install required system packages
   sudo apt-get install pkg-config libssl-dev
   ```

3. **Test Failures**
   ```bash
   # Run tests with detailed output
   cargo test -- --nocapture
   ```

4. **Performance Issues**
   ```bash
   # Check if release mode is being used
   cargo build --release
   
   # Enable CPU-specific optimizations
   export RUSTFLAGS="-C target-cpu=native"
   ```

### Debug Information

Enable debug logging:

```bash
export RUST_LOG=qasa=trace
export RUST_BACKTRACE=1
```

### Support

For technical support and issues:

1. Check the [project documentation](README.md)
2. Review [security guidelines](security_review.md)
3. Consult the [API documentation](docs/api/crypto_api.md)
4. Submit issues via the project repository

## Security Audit

### Self-Assessment

Perform regular security assessments:

```bash
# Run security tests
cargo test security

# Check for known vulnerabilities
cargo audit

# Analyze code quality
cargo clippy -- -D warnings
```

### External Audit

For production deployments, consider:

- Independent security audits
- Penetration testing
- Code review by cryptography experts
- Compliance validation

## Performance Optimization

### Compilation Flags

Optimize for different scenarios:

```bash
# Maximum performance
export RUSTFLAGS="-C target-cpu=native -C opt-level=3"

# Minimum size
export RUSTFLAGS="-C opt-level=s"

# Debug with optimizations
export RUSTFLAGS="-C opt-level=2 -g"
```

### Profiling

Profile performance bottlenecks:

```bash
# Install profiling tools
cargo install flamegraph

# Generate flame graph
cargo flamegraph --bench crypto_bench
```

## Publishing to Crates.io

### Prerequisites for Publishing

Before publishing to crates.io, ensure you have:

1. **Crates.io Account**: Create an account at https://crates.io
2. **API Token**: Generate an API token from https://crates.io/settings/tokens
3. **Git Tag**: Create and push a version tag

### Pre-Publishing Checklist

Complete this checklist before publishing:

- [ ] All tests pass: `cargo test`
- [ ] Benchmarks run successfully: `cargo bench`
- [ ] Documentation builds: `cargo doc --no-deps`
- [ ] No compiler warnings: `cargo clippy -- -D warnings`
- [ ] No security vulnerabilities: `cargo audit`
- [ ] Version updated in `Cargo.toml`
- [ ] CHANGELOG.md updated with release notes
- [ ] README.md badges and installation instructions updated
- [ ] Git tag created for the version
- [ ] All changes committed and pushed

### Publishing Steps

#### 1. Login to Crates.io

First-time setup (one-time only):

```bash
cargo login <your-api-token>
```

The token is stored in `~/.cargo/credentials` and will be used for all future publishes.

#### 2. Verify Package Contents

Check what will be published:

```bash
cargo package --list
```

Review the list to ensure no sensitive files are included.

#### 3. Dry Run

Test the publishing process without actually uploading:

```bash
cargo publish --dry-run
```

This will:
- Build the package
- Verify all dependencies
- Check that documentation builds
- Report any issues

#### 4. Create Git Tag

Tag the release version:

```bash
git tag -a v0.1.0 -m "Release version 0.1.0 - RFC 8439 compliant ChaCha20-Poly1305"
git push origin v0.1.0
```

#### 5. Publish

Publish to crates.io:

```bash
cargo publish
```

Once published, the crate will be available at `https://crates.io/crates/qasa` within a few minutes.

### Post-Publishing Tasks

After successful publication:

1. **Verify Publication**
   ```bash
   cargo search qasa
   ```

2. **Test Installation**
   ```bash
   # In a separate directory
   cargo new test_qasa
   cd test_qasa
   cargo add qasa@0.1.0
   cargo build
   ```

3. **Update GitHub Release**
   - Create a GitHub release for the tag
   - Include CHANGELOG.md content
   - Attach any pre-built binaries if applicable

4. **Announce the Release**
   - Update project website/documentation
   - Announce on relevant forums or mailing lists
   - Update any external documentation

### Versioning Strategy

QaSa follows [Semantic Versioning](https://semver.org/):

- **Major version (X.0.0)**: Breaking changes
- **Minor version (0.X.0)**: New features, backward compatible
- **Patch version (0.0.X)**: Bug fixes, backward compatible

Examples:
- `0.1.0` → `0.2.0`: New features added
- `0.1.0` → `0.1.1`: Bug fixes only
- `0.1.0` → `1.0.0`: Breaking changes or first stable release

### Yanking a Version

If a critical bug is found after publishing:

```bash
# Yank the problematic version
cargo yank --version 0.1.0

# To un-yank if needed
cargo yank --version 0.1.0 --undo
```

**Note**: Yanking does not delete the version but prevents new users from depending on it.

### Publishing Checklist Script

Create a script `scripts/pre-publish.sh`:

```bash
#!/bin/bash
set -e

echo "🔍 Running pre-publish checks..."

echo "✅ Running tests..."
cargo test --all-features

echo "✅ Running clippy..."
cargo clippy --all-features -- -D warnings

echo "✅ Checking formatting..."
cargo fmt -- --check

echo "✅ Running security audit..."
cargo audit

echo "✅ Building documentation..."
cargo doc --no-deps --all-features

echo "✅ Packaging..."
cargo package --list

echo "✅ Dry run..."
cargo publish --dry-run

echo ""
echo "✅ All checks passed!"
echo ""
echo "To publish, run:"
echo "  git tag -a v$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version') -m 'Release version $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')'"
echo "  git push origin --tags"
echo "  cargo publish"
```

Make it executable:

```bash
chmod +x scripts/pre-publish.sh
```

### Troubleshooting Publishing Issues

**Issue**: `error: failed to verify package`
```bash
# Solution: Check that all dependencies are available on crates.io
cargo package --list
```

**Issue**: `error: documentation failed to build`
```bash
# Solution: Fix documentation warnings
cargo doc --no-deps 2>&1 | grep warning
```

**Issue**: `error: some crates are not published`
```bash
# Solution: All dependencies must be published to crates.io
# Check Cargo.toml for path dependencies
```

This deployment guide ensures secure, reliable deployment of the QaSa cryptography module across various environments and use cases. 