#!/bin/bash

# QaSa Quick Deploy Script
# Deploys the QaSa web application quickly for immediate use

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}=======================================${NC}"
echo -e "${GREEN}QaSa Quick Deploy - Get Started Fast!${NC}"
echo -e "${BLUE}=======================================${NC}"

# Check if Docker is available
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    echo -e "${GREEN}Using Docker for quick deployment...${NC}"
    
    # Build and start with Docker
    echo -e "${YELLOW}Building Docker image...${NC}"
    docker-compose build qasa-web
    
    echo -e "${YELLOW}Starting QaSa application...${NC}"
    docker-compose up -d qasa-web
    
    echo -e "${GREEN}✅ QaSa is now running!${NC}"
    echo -e "${BLUE}🌐 Web Interface: http://localhost:8080${NC}"
    echo -e "${BLUE}🔗 P2P Network: Port 9000${NC}"
    
    echo -e "${YELLOW}To stop the application: docker-compose down${NC}"
    echo -e "${YELLOW}To view logs: docker-compose logs -f qasa-web${NC}"
    
else
    echo -e "${GREEN}Using native build for quick deployment...${NC}"
    
    # Check if we have the required tools
    if ! command -v go &> /dev/null; then
        echo "❌ Go is required but not installed. Please install Go 1.22+ first."
        exit 1
    fi
    
    if ! command -v cargo &> /dev/null; then
        echo "❌ Rust is required but not installed. Please install Rust 1.75+ first."
        exit 1
    fi
    
    # Quick native build
    echo -e "${YELLOW}Building crypto module...${NC}"
    cd src/crypto
    cargo build --release
    
    # Install shared library
    sudo cp target/release/libqasa_crypto.so /usr/local/lib/ 2>/dev/null || \
    sudo cp target/release/libqasa_crypto.dylib /usr/local/lib/ 2>/dev/null || true
    sudo ldconfig 2>/dev/null || true
    
    cd ../../
    
    echo -e "${YELLOW}Building web application...${NC}"
    cd src/web
    go build -o qasa-web main.go
    
    echo -e "${YELLOW}Starting QaSa application...${NC}"
    ./qasa-web --port 9000 --web-port 8080 &
    PID=$!
    echo $PID > qasa-web.pid
    
    cd ../../
    
    echo -e "${GREEN}✅ QaSa is now running!${NC}"
    echo -e "${BLUE}🌐 Web Interface: http://localhost:8080${NC}"
    echo -e "${BLUE}🔗 P2P Network: Port 9000${NC}"
    echo -e "${BLUE}📝 Process ID: $PID${NC}"
    
    echo -e "${YELLOW}To stop the application: kill $PID${NC}"
    echo -e "${YELLOW}Or run: kill \$(cat src/web/qasa-web.pid)${NC}"
fi

echo -e "${BLUE}=======================================${NC}"
echo -e "${GREEN}🎉 QaSa deployment completed!${NC}"
echo -e "${BLUE}📚 For more deployment options, see DEPLOYMENT.md${NC}"
echo -e "${BLUE}=======================================${NC}" 