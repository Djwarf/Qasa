#!/bin/bash

set -e  # Exit on any error

# Build the Rust crypto library
echo "Building Rust crypto library..."
cd ../../crypto
cargo build --release

# Set up the library path
export LD_LIBRARY_PATH=$(pwd)/target/release:$LD_LIBRARY_PATH

# Go back to the network/examples directory
cd ../network/examples

# Build and run the Go test program
echo "Building Go test program..."
go build -o crypto_test rust_crypto_test.go

echo "Running crypto test..."
./crypto_test 