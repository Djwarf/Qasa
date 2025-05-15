#!/bin/bash
# QaSa Web Interface Setup
# This script copies the web files to the correct location for the web server

# Find script and project directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
WEB_SRC_DIR="$PROJECT_DIR/src/web"
WEB_DEST_DIR="$SCRIPT_DIR/src/web"

# Create web directories if they don't exist
mkdir -p "$WEB_DEST_DIR"

# Copy web files
echo "Copying web files from $WEB_SRC_DIR to $WEB_DEST_DIR..."
cp -f "$WEB_SRC_DIR/index.html" "$WEB_DEST_DIR/"
cp -f "$WEB_SRC_DIR/app.js" "$WEB_DEST_DIR/"
cp -f "$WEB_SRC_DIR/styles.css" "$WEB_DEST_DIR/"

echo "Web files copied successfully!"
echo "To use the web interface, run QaSa with the --web flag, e.g.:"
echo "./qasa-run.sh --web 8080" 