#!/bin/bash

# QaSa Deployment Script
# This script handles building, testing, and deploying the QaSa secure chat application

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEFAULT_PORT=8080
DEFAULT_NETWORK_PORT=9000
DEPLOYMENT_MODE="development"
BUILD_ONLY=false
SKIP_TESTS=false
USE_DOCKER=true

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "QaSa Deployment Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -m, --mode MODE           Deployment mode: development, production, staging (default: development)"
    echo "  -p, --port PORT           Web interface port (default: 8080)"
    echo "  -n, --network-port PORT   P2P network port (default: 9000)"
    echo "  -b, --build-only          Only build, don't deploy"
    echo "  -t, --skip-tests          Skip running tests"
    echo "  -d, --no-docker           Don't use Docker for deployment"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Development deployment"
    echo "  $0 --mode production --port 80        # Production deployment on port 80"
    echo "  $0 --build-only                       # Just build the application"
    echo "  $0 --no-docker --port 3000            # Native deployment on port 3000"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mode)
            DEPLOYMENT_MODE="$2"
            shift 2
            ;;
        -p|--port)
            DEFAULT_PORT="$2"
            shift 2
            ;;
        -n|--network-port)
            DEFAULT_NETWORK_PORT="$2"
            shift 2
            ;;
        -b|--build-only)
            BUILD_ONLY=true
            shift
            ;;
        -t|--skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        -d|--no-docker)
            USE_DOCKER=false
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate deployment mode
if [[ ! "$DEPLOYMENT_MODE" =~ ^(development|production|staging)$ ]]; then
    print_error "Invalid deployment mode: $DEPLOYMENT_MODE"
    exit 1
fi

print_status "Starting QaSa deployment in $DEPLOYMENT_MODE mode..."

# Check required tools
check_dependencies() {
    print_status "Checking dependencies..."
    
    if [ "$USE_DOCKER" = true ]; then
        if ! command -v docker &> /dev/null; then
            print_error "Docker is required but not installed"
            exit 1
        fi
        
        if ! command -v docker-compose &> /dev/null; then
            print_error "Docker Compose is required but not installed"
            exit 1
        fi
    else
        if ! command -v go &> /dev/null; then
            print_error "Go is required but not installed"
            exit 1
        fi
        
        if ! command -v cargo &> /dev/null; then
            print_error "Rust/Cargo is required but not installed"
            exit 1
        fi
    fi
    
    print_success "Dependencies check passed"
}

# Run tests
run_tests() {
    if [ "$SKIP_TESTS" = true ]; then
        print_warning "Skipping tests as requested"
        return
    fi
    
    print_status "Running tests..."
    
    # Test crypto module
    print_status "Testing Rust crypto module..."
    cd src/crypto
    cargo test
    cd "$SCRIPT_DIR"
    
    # Test network module
    print_status "Testing Go network module..."
    cd src/network
    go test -v ./...
    cd "$SCRIPT_DIR"
    
    print_success "All tests passed"
}

# Build using Docker
build_docker() {
    print_status "Building Docker image..."
    
    # Build the main application image
    docker build -t qasa-web:latest .
    
    print_success "Docker image built successfully"
}

# Build natively
build_native() {
    print_status "Building natively..."
    
    # Build crypto module
    print_status "Building Rust crypto module..."
    cd src/crypto
    cargo build --release
    
    # Install the shared library
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo cp target/release/libqasa_crypto.so /usr/local/lib/
        sudo ldconfig
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        sudo cp target/release/libqasa_crypto.dylib /usr/local/lib/
    fi
    
    cd "$SCRIPT_DIR"
    
    # Build network module
    print_status "Building Go network module..."
    cd src/network
    go build -o qasa-network main.go
    cd "$SCRIPT_DIR"
    
    # Build web module
    print_status "Building Go web module..."
    cd src/web
    go build -o qasa-web main.go
    cd "$SCRIPT_DIR"
    
    print_success "Native build completed"
}

# Deploy using Docker
deploy_docker() {
    print_status "Deploying with Docker..."
    
    # Create environment file
    cat > .env << EOF
QASA_WEB_PORT=$DEFAULT_PORT
QASA_NETWORK_PORT=$DEFAULT_NETWORK_PORT
QASA_MODE=$DEPLOYMENT_MODE
EOF
    
    # Stop existing containers
    docker-compose down 2>/dev/null || true
    
    if [ "$DEPLOYMENT_MODE" = "production" ]; then
        # Check for SSL certificates in production
        if [ ! -f "ssl/cert.pem" ] || [ ! -f "ssl/key.pem" ]; then
            print_warning "SSL certificates not found. Generating self-signed certificates for testing..."
            mkdir -p ssl
            openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes \
                -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        fi
        
        # Deploy with nginx
        docker-compose --profile production up -d
        print_success "Production deployment started with nginx reverse proxy"
        print_status "Application available at:"
        print_status "  HTTP:  http://localhost:80"
        print_status "  HTTPS: https://localhost:443"
    else
        # Development/staging deployment
        docker-compose up -d qasa-web
        print_success "Development deployment started"
        print_status "Application available at: http://localhost:$DEFAULT_PORT"
    fi
    
    # Show container status
    print_status "Container status:"
    docker-compose ps
}

# Deploy natively
deploy_native() {
    print_status "Deploying natively..."
    
    # Create systemd service file for production
    if [ "$DEPLOYMENT_MODE" = "production" ]; then
        print_status "Creating systemd service..."
        
        sudo tee /etc/systemd/system/qasa-web.service > /dev/null << EOF
[Unit]
Description=QaSa Secure Chat Web Application
After=network.target

[Service]
Type=simple
User=qasa
Group=qasa
WorkingDirectory=$SCRIPT_DIR/src/web
ExecStart=$SCRIPT_DIR/src/web/qasa-web --port $DEFAULT_NETWORK_PORT --web-port $DEFAULT_PORT
Restart=always
RestartSec=5
Environment=HOME=/home/qasa

[Install]
WantedBy=multi-user.target
EOF
        
        # Create qasa user if it doesn't exist
        if ! id "qasa" &>/dev/null; then
            sudo useradd -r -s /bin/false qasa
        fi
        
        # Set proper permissions
        sudo chown -R qasa:qasa "$SCRIPT_DIR"
        
        # Start and enable the service
        sudo systemctl daemon-reload
        sudo systemctl enable qasa-web
        sudo systemctl start qasa-web
        
        print_success "Production service started and enabled"
        print_status "Service status:"
        sudo systemctl status qasa-web --no-pager
    else
        # Development deployment
        print_status "Starting development server..."
        cd src/web
        ./qasa-web --port $DEFAULT_NETWORK_PORT --web-port $DEFAULT_PORT &
        PID=$!
        echo $PID > qasa-web.pid
        
        print_success "Development server started (PID: $PID)"
        print_status "Application available at: http://localhost:$DEFAULT_PORT"
        print_status "To stop: kill $PID"
    fi
}

# Main deployment logic
main() {
    print_status "QaSa Deployment Script"
    print_status "======================"
    print_status "Mode: $DEPLOYMENT_MODE"
    print_status "Web Port: $DEFAULT_PORT"
    print_status "Network Port: $DEFAULT_NETWORK_PORT"
    print_status "Use Docker: $USE_DOCKER"
    print_status ""
    
    # Check dependencies
    check_dependencies
    
    # Run tests
    run_tests
    
    # Build
    if [ "$USE_DOCKER" = true ]; then
        build_docker
    else
        build_native
    fi
    
    # Deploy (unless build-only)
    if [ "$BUILD_ONLY" = false ]; then
        if [ "$USE_DOCKER" = true ]; then
            deploy_docker
        else
            deploy_native
        fi
        
        print_success "Deployment completed successfully!"
        
        # Health check
        print_status "Performing health check..."
        sleep 5
        
        if curl -f "http://localhost:$DEFAULT_PORT" >/dev/null 2>&1; then
            print_success "Health check passed - application is responding"
        else
            print_warning "Health check failed - application may still be starting"
        fi
    else
        print_success "Build completed successfully!"
    fi
}

# Cleanup function
cleanup() {
    if [ $? -ne 0 ]; then
        print_error "Deployment failed!"
        if [ "$USE_DOCKER" = true ]; then
            print_status "Checking container logs..."
            docker-compose logs --tail=20
        fi
    fi
}

# Set up cleanup trap
trap cleanup EXIT

# Run main function
main 