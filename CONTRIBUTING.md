# Contributing to QaSa

Thank you for your interest in contributing to QaSa! This document provides guidelines and instructions for contributing to this quantum-safe chat application.

## Code of Conduct

Please be respectful and considerate of others when contributing to this project. We aim to foster an inclusive and welcoming community.

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
   git checkout -b feature/your-feature-name
   ```

2. Make your changes, following our coding standards.

3. Add tests for your changes when applicable.

4. Ensure all tests pass:
   ```bash
   # For Rust components
   cd src/crypto
   cargo test
   
   # For Go components
   cd src/network
   go test ./...
   ```

5. Commit your changes with a clear, descriptive message:
   ```bash
   git commit -m "Add feature: your feature description"
   ```

6. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

7. Open a pull request against the main repository.

## Coding Standards

### Rust

- Follow the Rust style guide (rustfmt).
- Document all public APIs with doc comments.
- Use descriptive variable names.
- Write comprehensive unit tests.
- Use Rust's type system effectively.
- Handle errors appropriately.

### Go

- Follow the Go style guide (gofmt).
- Document all exported functions and types.
- Follow Go's error handling patterns.
- Write comprehensive unit tests.
- Use meaningful variable and function names.

## Pull Request Process

1. Ensure your code passes all tests.
2. Update documentation as needed.
3. Ensure your code adheres to our style guidelines.
4. Your pull request will be reviewed by the maintainers.
5. Address any feedback from the review.
6. Once approved, your changes will be merged.

## Security Considerations

As QaSa is a security-focused application, please pay special attention to:

- Proper handling of cryptographic keys and secrets
- Secure network communications
- Input validation and sanitization
- Avoiding common security pitfalls
- Not committing sensitive information or credentials

## Reporting Security Issues

If you discover a security vulnerability, please do NOT open an issue or pull request. Instead, send an email to djwarfqasa@proton.me with details of the vulnerability.

## License

By contributing to QaSa, you agree that your contributions will be licensed under the same license as the project (MIT License). 