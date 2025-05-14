#!/bin/bash
# QaSa Secure Chat Simple Launcher
# This script provides a simple way to launch the QaSa secure chat application
# without requiring sudo privileges

# Find script and project directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CRYPTO_DIR="$PROJECT_DIR/src/crypto"
NETWORK_DIR="$SCRIPT_DIR"
MAIN_BIN="$NETWORK_DIR/qasa-network"

# Build the Rust crypto library if needed
if [ ! -f "$CRYPTO_DIR/target/release/libqasa_crypto.so" ]; then
  echo "Building Rust cryptography library..."
  (cd "$CRYPTO_DIR" && cargo build --release)
  if [ $? -ne 0 ]; then
    echo "Failed to build Rust cryptography library."
    exit 1
  fi
  echo "Crypto library build successful."
fi

# Set LD_LIBRARY_PATH to include the crypto library
export LD_LIBRARY_PATH="$CRYPTO_DIR/target/release:$LD_LIBRARY_PATH"

# Run build_crypto.sh to ensure FFI bindings are up-to-date
if [ -f "$NETWORK_DIR/build_crypto.sh" ]; then
  echo "Setting up crypto bindings..."
  (cd "$NETWORK_DIR" && ./build_crypto.sh)
  if [ $? -ne 0 ]; then
    echo "Failed to set up crypto bindings."
    exit 1
  fi
fi

# Check if network binary exists, if not, build it
if [ ! -f "$MAIN_BIN" ] || [ "$NETWORK_DIR/main.go" -nt "$MAIN_BIN" ]; then
  echo "Building QaSa network module..."
  (cd "$NETWORK_DIR" && go build -o "$MAIN_BIN" main.go)
  if [ $? -ne 0 ]; then
    echo "Failed to build QaSa network module."
    exit 1
  fi
  echo "Network build successful."
fi

# Launch the application with all arguments passed to this script
echo "Launching QaSa secure chat..."
"$MAIN_BIN" "$@" 