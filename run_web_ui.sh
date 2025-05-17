#!/bin/bash

# QaSa Web UI Launcher

# Set the base directory to the script location
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$BASE_DIR"

# Colors for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=======================================${NC}"
echo -e "${GREEN}Starting QaSa Secure Chat Application${NC}"
echo -e "${BLUE}=======================================${NC}"

# Check if the network binary exists
if [ ! -f "$BASE_DIR/src/network/qasa-network" ]; then
    echo -e "${YELLOW}Building network module...${NC}"
    cd "$BASE_DIR/src/network"
    go build -o qasa-network
    
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}Failed to build network module. Building crypto module first...${NC}"
        cd "$BASE_DIR/src/crypto"
        cargo build --release
        
        if [ $? -ne 0 ]; then
            echo "Failed to build crypto module. Please check for errors."
            exit 1
        fi
        
        # Try building network module again
        cd "$BASE_DIR/src/network"
        ./build_crypto.sh
        go build -o qasa-network
        
        if [ $? -ne 0 ]; then
            echo "Failed to build network module. Please check for errors."
            exit 1
        fi
    fi
fi

# Create a new QASA directory in the user's home directory if it doesn't exist
QASA_DIR="$HOME/.qasa"
mkdir -p "$QASA_DIR"

# Check if there are keys, if not, generate them
KEY_DIR="$QASA_DIR/keys"
if [ ! -d "$KEY_DIR" ] || [ -z "$(ls -A "$KEY_DIR" 2>/dev/null)" ]; then
    echo -e "${YELLOW}No keys found. Generating default keys...${NC}"
    cd "$BASE_DIR/src/network"
    ./qasa-network gen-keys
fi

# Default port for the web interface
DEFAULT_PORT=8080
PORT=${1:-$DEFAULT_PORT}

echo -e "${GREEN}Starting web interface on port $PORT...${NC}"
echo -e "${BLUE}======================================${NC}"
echo -e "${YELLOW}Open your browser and navigate to:${NC}"
echo -e "${GREEN}http://localhost:$PORT${NC}"
echo -e "${BLUE}======================================${NC}"

# Start the network module with web interface
cd "$BASE_DIR/src/network"
./qasa-network -web $PORT

# If we get here, the application was stopped
echo -e "${BLUE}======================================${NC}"
echo -e "${GREEN}QaSa application stopped.${NC}"
echo -e "${BLUE}======================================${NC}" 