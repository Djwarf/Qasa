# Contributing to QaSa Cryptography Module

Thank you for your interest in contributing to the QaSa post-quantum cryptography module! This document provides guidelines and instructions for contributing to this quantum-safe cryptographic implementation.

## Code of Conduct

Please be respectful and considerate of others when contributing to this project. We aim to foster an inclusive and welcoming community focused on advancing post-quantum cryptography.

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/qasa.git
   cd qasa
   ```
3. Add the original repository as an upstream remote:
   ```bash
   git remote add upstream https://github.com/qasa/qasa.git
   ```

## Development Workflow

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/crypto-your-feature-name
   ```

2. Make your changes, following our coding standards.

3. Add comprehensive tests for your changes:
   ```bash
   cd src/crypto
   cargo test
   ```

4. Run benchmarks to ensure performance is maintained:
   ```bash
   cargo bench
   ```

5. Ensure security tests pass:
   ```bash
   cargo test security
   cargo test constant_time
   ```

6. Update documentation:
   ```bash
   cargo doc --open
   ```

7. Commit your changes with a clear, descriptive message:
   ```bash
   git commit -m "crypto: Add feature - your feature description"
   ```

8. Push your branch to your fork:
   ```bash
   git push origin feature/crypto-your-feature-name
   ```

9. Open a pull request against the main repository.

## Coding Standards

### Rust Cryptography

- **Follow the Rust style guide (rustfmt)**
- **Document all public APIs with comprehensive doc comments**
- **Use descriptive variable names, especially for cryptographic operations**
- **Write comprehensive unit tests and integration tests**
- **Use Rust's type system effectively for compile-time security**
- **Handle errors appropriately with proper error types**
- **Implement constant-time operations for cryptographic functions**
- **Use secure memory handling with zeroization**

### Cryptographic Implementation Guidelines

1. **Security First**: All changes must maintain or improve security posture
2. **Constant-Time Operations**: Ensure all cryptographic operations are constant-time
3. **Memory Safety**: Use secure memory allocation and zeroization
4. **Error Handling**: Implement robust error handling for all failure modes
5. **Testing**: Comprehensive testing including edge cases and security tests
6. **Documentation**: Clear documentation of security properties and usage

### Code Organization

- Place new algorithms in appropriate module directories (`kyber/`, `dilithium/`, `aes/`, etc.)
- Add public API functions to the module's `mod.rs` file
- Include both unit tests and integration tests
- Add benchmarks for performance-critical operations
- Create example code demonstrating functionality

## Types of Contributions

### Algorithm Implementations

- New post-quantum algorithms
- Optimizations for existing algorithms
- Platform-specific optimizations
- Memory usage improvements

### Security Enhancements

- Side-channel resistance improvements
- Secure memory handling enhancements
- Additional security validations
- Constant-time operation implementations

### Performance Optimizations

- SIMD implementations
- Hardware acceleration support
- Memory usage optimizations
- Cache-friendly implementations

### Documentation

- API documentation improvements
- Security guide updates
- Example code and tutorials
- Performance analysis documentation

## Pull Request Process

1. **Code Quality**: Ensure your code passes all tests and follows style guidelines
2. **Documentation**: Update all relevant documentation
3. **Security Review**: All cryptographic changes require thorough security review
4. **Performance Testing**: Benchmark performance impact
5. **Peer Review**: Your pull request will be reviewed by cryptography experts
6. **Testing**: Comprehensive test coverage including security tests
7. **Integration**: Address all feedback before merge

### Pull Request Checklist

- [ ] All tests pass (`cargo test`)
- [ ] Security tests pass (`cargo test security`)
- [ ] Benchmarks run successfully (`cargo bench`)
- [ ] Documentation updated (`cargo doc`)
- [ ] Code formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Security review conducted
- [ ] Examples updated if needed

## Security Considerations

As the QaSa cryptography module is security-critical, please pay special attention to:

### Cryptographic Security

- **Key Material Handling**: Proper secure storage and zeroization of keys
- **Random Number Generation**: Use cryptographically secure randomness
- **Side-Channel Resistance**: Implement constant-time operations
- **Algorithm Implementation**: Follow specifications exactly
- **Memory Safety**: Prevent memory disclosure attacks

### Code Security

- **Input Validation**: Validate all inputs thoroughly
- **Error Handling**: Never leak sensitive information in errors
- **Secure Defaults**: Use secure configurations by default
- **Dependency Management**: Keep dependencies updated and audited

### Testing Security

- **Security Tests**: Include tests for security properties
- **Fuzzing**: Add fuzzing tests for input validation
- **Constant-Time Tests**: Verify constant-time properties
- **Memory Safety Tests**: Test for memory leaks and corruption

## Reporting Security Issues

**Critical**: If you discover a security vulnerability, please do NOT open an issue or pull request. 

Instead, send an email to djwarfqasa@proton.me with:
- Detailed description of the vulnerability
- Proof-of-concept code (if applicable)
- Suggested mitigation strategies
- Your contact information

We will respond within 48 hours and work with you to address the issue responsibly.

## Development Environment

### Required Tools

- Rust 1.60+ with Cargo
- C compiler (GCC or Clang)
- Git
- Text editor with Rust support

### Recommended Tools

- rust-analyzer for IDE support
- cargo-audit for security audits
- cargo-fuzz for fuzzing
- flamegraph for performance profiling

### Setup

```bash
# Install required Rust components
rustup update
rustup component add rustfmt clippy

# Install development tools
cargo install cargo-audit cargo-fuzz flamegraph

# Build and test
cd src/crypto
cargo build --release
cargo test
cargo bench
```

## Documentation Standards

- **API Documentation**: Complete rustdoc for all public items
- **Security Properties**: Document security guarantees and limitations
- **Usage Examples**: Provide clear usage examples
- **Performance Notes**: Document performance characteristics
- **Safety Requirements**: Explain safe usage patterns

## Testing Requirements

### Unit Tests

- Test all public functions
- Test error conditions
- Test edge cases and boundary conditions
- Test security properties

### Integration Tests

- Test complete workflows
- Test interoperability between components
- Test configuration scenarios

### Security Tests

- Constant-time verification
- Memory zeroization verification
- Input validation testing
- Cryptographic property verification

### Performance Tests

- Benchmark all public operations
- Test memory usage
- Profile performance regressions

## License

By contributing to the QaSa cryptography module, you agree that your contributions will be licensed under the same license as the project (MIT License).

Your contributions must be your original work or properly attributed open-source code compatible with the MIT License. 