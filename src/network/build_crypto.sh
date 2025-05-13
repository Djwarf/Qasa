#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CRYPTO_DIR="$SCRIPT_DIR/../crypto"
TARGET_DIR="$CRYPTO_DIR/target/release"

echo "Building Rust cryptography library..."

# Go to the Rust crypto directory
cd "$CRYPTO_DIR"

# Build the Rust library in release mode
cargo build --release

# Copy the header file to the release directory
cp "$SCRIPT_DIR/encryption/qasa_crypto.h" "$TARGET_DIR/"

# Create symlinks for the library
cd "$SCRIPT_DIR/encryption"
mkdir -p lib

# Linux
if [ "$(uname)" == "Linux" ]; then
    ln -sf "$TARGET_DIR/libqasa_crypto.so" lib/
    echo "Created symlink for Linux library"
# macOS
elif [ "$(uname)" == "Darwin" ]; then
    ln -sf "$TARGET_DIR/libqasa_crypto.dylib" lib/
    echo "Created symlink for macOS library"
# Windows (MSYS or Git Bash)
elif [ "$(expr substr $(uname -s) 1 5)" == "MINGW" ] || [ "$(expr substr $(uname -s) 1 4)" == "MSYS" ]; then
    ln -sf "$TARGET_DIR/qasa_crypto.dll" lib/
    echo "Created symlink for Windows library"
else
    echo "Unknown platform, couldn't create symlinks"
fi

echo "Rust crypto library built successfully!" 