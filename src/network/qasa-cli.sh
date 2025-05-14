#!/bin/bash
# QaSa Secure Chat CLI Launcher
# This script provides a convenient way to launch the QaSa secure chat application

# Default values
PORT=0
CONFIG_DIR="$HOME/.qasa"
NO_MDNS=false
USE_DHT=false
REQUIRE_AUTH=false
NO_OFFLINE_QUEUE=false
BOOTSTRAP_NODE=""
CONNECT_TO=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --port|-p)
      PORT="$2"
      shift 2
      ;;
    --config|-c)
      CONFIG_DIR="$2"
      shift 2
      ;;
    --no-mdns)
      NO_MDNS=true
      shift
      ;;
    --dht)
      USE_DHT=true
      shift
      ;;
    --auth)
      REQUIRE_AUTH=true
      shift
      ;;
    --no-offline-queue)
      NO_OFFLINE_QUEUE=true
      shift
      ;;
    --bootstrap|-b)
      BOOTSTRAP_NODE="$2"
      shift 2
      ;;
    --connect|-C)
      CONNECT_TO="$2"
      shift 2
      ;;
    --help|-h)
      echo "QaSa Secure Chat CLI"
      echo "Usage: $0 [options]"
      echo
      echo "Options:"
      echo "  --port, -p PORT           Port to listen on (0 for random port)"
      echo "  --config, -c DIR          Configuration directory (default: ~/.qasa)"
      echo "  --no-mdns                 Disable mDNS discovery"
      echo "  --dht                     Enable DHT-based peer discovery"
      echo "  --auth                    Require peer authentication"
      echo "  --no-offline-queue        Disable offline message queuing"
      echo "  --bootstrap, -b NODE      Add a bootstrap node"
      echo "  --connect, -C PEER        Peer to connect to"
      echo "  --help, -h                Display this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information."
      exit 1
      ;;
  esac
done

# Ensure the config directory exists
mkdir -p "$CONFIG_DIR"

# Find script and project directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CRYPTO_DIR="$PROJECT_DIR/src/crypto"
NETWORK_DIR="$SCRIPT_DIR"
MAIN_BIN="$NETWORK_DIR/qasa-network"

# Build the Rust crypto library if needed
if [ ! -f "$CRYPTO_DIR/target/release/libqasa_crypto.so" ] || [ ! -f "/usr/local/lib/libqasa_crypto.so" ]; then
  echo "Building Rust cryptography library..."
  (cd "$CRYPTO_DIR" && cargo build --release)
  if [ $? -ne 0 ]; then
    echo "Failed to build Rust cryptography library."
    exit 1
  fi
  
  # Copy the shared library to a system directory or update LD_LIBRARY_PATH
  if [ -w "/usr/local/lib" ]; then
    echo "Installing shared library to /usr/local/lib..."
    sudo cp "$CRYPTO_DIR/target/release/libqasa_crypto.so" /usr/local/lib/
    sudo ldconfig
  else
    echo "Setting LD_LIBRARY_PATH to include the crypto library directory..."
    export LD_LIBRARY_PATH="$CRYPTO_DIR/target/release:$LD_LIBRARY_PATH"
  fi
  
  echo "Crypto library build successful."
fi

# Run build_crypto.sh to ensure FFI bindings are up-to-date
if [ -f "$NETWORK_DIR/build_crypto.sh" ]; then
  echo "Setting up crypto bindings..."
  (cd "$NETWORK_DIR" && ./build_crypto.sh)
  if [ $? -ne 0 ]; then
    echo "Failed to set up crypto bindings."
    exit 1
  fi
fi

# Build up command arguments
ARGS=()
ARGS+=("--port" "$PORT")
ARGS+=("--config" "$CONFIG_DIR")

if [ "$NO_MDNS" = true ]; then
  ARGS+=("--no-mdns")
fi

if [ "$USE_DHT" = true ]; then
  ARGS+=("--dht")
fi

if [ "$REQUIRE_AUTH" = true ]; then
  ARGS+=("--auth")
fi

if [ "$NO_OFFLINE_QUEUE" = true ]; then
  ARGS+=("--no-offline-queue")
fi

if [ -n "$BOOTSTRAP_NODE" ]; then
  ARGS+=("--bootstrap" "$BOOTSTRAP_NODE")
fi

if [ -n "$CONNECT_TO" ]; then
  ARGS+=("--connect" "$CONNECT_TO")
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

# Make sure the LD_LIBRARY_PATH includes the crypto library directory
# even if we didn't rebuild the library above
if [ ! -f "/usr/local/lib/libqasa_crypto.so" ]; then
  export LD_LIBRARY_PATH="$CRYPTO_DIR/target/release:$LD_LIBRARY_PATH"
fi

# Launch the application
echo "Launching QaSa secure chat..."
"$MAIN_BIN" "${ARGS[@]}" 