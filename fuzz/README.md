# Fuzzing for QaSa Cryptography Module

This directory contains fuzzing targets for the QaSa cryptography module, using `cargo-fuzz` and `libfuzzer`.

## Setup

To use these fuzzing targets, you need to have the nightly Rust toolchain and `cargo-fuzz` installed:

```bash
# Install the nightly toolchain
rustup toolchain install nightly

# Install cargo-fuzz
cargo install cargo-fuzz
```

## Available Fuzz Targets

The following fuzz targets are available:

1. **fuzz_kyber**: Tests Kyber key encapsulation and decapsulation
2. **fuzz_dilithium**: Tests Dilithium signature generation and verification
3. **fuzz_aes_gcm**: Tests AES-GCM encryption and decryption
4. **fuzz_secure_memory**: Tests secure memory operations with CanaryBuffer
5. **fuzz_high_level_api**: Tests high-level API functions

## Running Fuzz Tests

To run a fuzz test, use the following command:

```bash
cargo +nightly fuzz run <target_name> -- -max_len=4096
```

For example:

```bash
cargo +nightly fuzz run fuzz_kyber -- -max_len=4096
```

You can adjust the maximum input length and other fuzzing parameters as needed.

## Continuous Fuzzing

For continuous fuzzing, you might want to run with a longer timeout:

```bash
cargo +nightly fuzz run <target_name> -- -max_len=4096 -max_total_time=3600
```

This will run the fuzzer for 1 hour.

## Corpus Management

To save and reuse a corpus of test cases:

```bash
# Create a corpus directory
mkdir -p fuzz/corpus/<target_name>

# Run fuzzing with corpus
cargo +nightly fuzz run <target_name> fuzz/corpus/<target_name> -- -max_len=4096
```

## Crash Analysis

When a crash is found, it will be saved in `fuzz/artifacts/<target_name>/`. You can reproduce the crash with:

```bash
cargo +nightly fuzz run <target_name> fuzz/artifacts/<target_name>/<crash_file>
```

## Adding New Fuzz Targets

To add a new fuzz target:

```bash
cargo +nightly fuzz add <target_name>
```

Then edit the generated file in `fuzz/fuzz_targets/<target_name>.rs` to implement your fuzzing logic. 