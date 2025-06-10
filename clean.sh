#!/bin/bash

# QaSa Cryptography Module Cleanup Script
# Removes build artifacts, temporary files, and runtime data

set -e

echo "Cleaning QaSa Cryptography Module..."

# Remove build artifacts
echo "Removing build artifacts..."
find . -name "target" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.exe" -delete 2>/dev/null || true
find . -name "*.so" -delete 2>/dev/null || true
find . -name "*.dylib" -delete 2>/dev/null || true
find . -name "*.dll" -delete 2>/dev/null || true

# Remove temporary files
echo "Removing temporary files..."
find . -name "*.log" -delete 2>/dev/null || true
find . -name "*.tmp" -delete 2>/dev/null || true
find . -name "*~" -delete 2>/dev/null || true
find . -name ".DS_Store" -delete 2>/dev/null || true
find . -name "Thumbs.db" -delete 2>/dev/null || true

# Remove runtime data directories
echo "Removing runtime data..."
find . -name ".qasa" -type d -exec rm -rf {} + 2>/dev/null || true

# Clean Go module cache for this project
echo "Cleaning Go modules..."
cd src && go clean -modcache 2>/dev/null || true
cd ..

# Clean Rust target directories
echo "Cleaning Rust targets..."
cd src/crypto && cargo clean 2>/dev/null || true
cd ../..

# Remove empty directories (except git)
echo "Removing empty directories..."
find . -type d -empty -not -path "./.git/*" -delete 2>/dev/null || true

echo "Cleanup complete!"
echo ""
echo "To rebuild the crypto module:"
echo "  1. cd src/crypto && cargo build --release"
echo "  2. cargo test"
echo "  3. cargo run --example secure_communication" 