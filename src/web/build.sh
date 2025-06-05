#!/bin/bash
set -e

echo "Building QaSa Web Module..."

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Change to the web module directory
cd "$SCRIPT_DIR"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go first."
    exit 1
fi

# Initialize go modules if needed
if [ ! -f go.sum ]; then
    echo "Initializing Go modules..."
    go mod tidy
fi

# Build the web application
echo "Building web application..."
go build -o qasa-web main.go

echo "Build completed successfully!"
echo "You can run the web application with: ./qasa-web" 