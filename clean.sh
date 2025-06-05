#!/bin/bash

# QaSa Project Cleanup Script
# Removes build artifacts, temporary files, and runtime data

set -e

echo "🧹 Cleaning QaSa project..."

# Remove build artifacts
echo "Removing build artifacts..."
find . -name "target" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.exe" -delete 2>/dev/null || true
find . -name "*.so" -delete 2>/dev/null || true
find . -name "*.dylib" -delete 2>/dev/null || true
find . -name "*.dll" -delete 2>/dev/null || true
find . -name "qasa-*" -type f -executable -delete 2>/dev/null || true

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
find . -name "node_modules" -type d -exec rm -rf {} + 2>/dev/null || true

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

echo "✅ Cleanup complete!"
echo ""
echo "To rebuild the project:"
echo "  1. cd src && go mod tidy"
echo "  2. cd crypto && cargo build --release"
echo "  3. Run ./run_web_ui.sh to start the application" 