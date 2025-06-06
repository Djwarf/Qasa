#!/bin/bash

# QaSa Enhanced Web Interface Deployment Script
# This script stops existing containers and deploys the updated QaSa application

set -e

echo "🚀 QaSa Enhanced Deployment Script"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if Docker is available
check_docker() {
    print_status "Checking Docker availability..."
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Test Docker permissions
    if ! docker ps &> /dev/null; then
        print_warning "Docker requires sudo permissions"
        DOCKER_CMD="sudo docker"
    else
        DOCKER_CMD="docker"
    fi
    
    print_success "Docker available with command: $DOCKER_CMD"
}

# Stop existing containers
stop_existing_containers() {
    print_status "Stopping existing QaSa containers..."
    
    # Find and stop any QaSa containers
    local containers=$($DOCKER_CMD ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Image}}" | grep -E "(qasa|QaSa)" || true)
    
    if [ -n "$containers" ]; then
        echo "$containers"
        local container_ids=$($DOCKER_CMD ps -a --format "{{.ID}}" --filter "name=qasa" || true)
        
        if [ -n "$container_ids" ]; then
            print_status "Stopping containers: $container_ids"
            $DOCKER_CMD stop $container_ids || true
            
            print_status "Removing containers: $container_ids"
            $DOCKER_CMD rm $container_ids || true
            
            print_success "Existing QaSa containers stopped and removed"
        fi
    else
        print_status "No existing QaSa containers found"
    fi
    
    # Check for processes on our ports
    print_status "Checking ports 8080 and 9000..."
    local port_8080=$(ss -tlnp | grep :8080 || true)
    local port_9000=$(ss -tlnp | grep :9000 || true)
    
    if [ -n "$port_8080" ]; then
        print_warning "Port 8080 is in use:"
        echo "$port_8080"
    fi
    
    if [ -n "$port_9000" ]; then
        print_warning "Port 9000 is in use:"
        echo "$port_9000"
    fi
}

# Build the Docker image
build_image() {
    print_status "Building QaSa Docker image with enhanced features..."
    
    # Ensure we're in the right directory
    if [ ! -f "Dockerfile" ]; then
        print_error "Dockerfile not found. Please run this script from the QaSa project root."
        exit 1
    fi
    
    # Build the image
    print_status "Running: $DOCKER_CMD build -t qasa-enhanced ."
    $DOCKER_CMD build -t qasa-enhanced . || {
        print_error "Docker build failed"
        exit 1
    }
    
    print_success "QaSa Docker image built successfully"
}

# Deploy the container
deploy_container() {
    print_status "Deploying QaSa container with enhanced web interface..."
    
    # Run the container with enhanced features
    local container_id=$($DOCKER_CMD run -d \
        --name qasa-enhanced \
        -p 8080:8080 \
        -p 9000:9000 \
        --restart unless-stopped \
        qasa-enhanced) || {
        print_error "Failed to start QaSa container"
        exit 1
    }
    
    print_success "QaSa container deployed successfully"
    print_success "Container ID: $container_id"
    
    # Wait a moment for the container to start
    print_status "Waiting for services to initialize..."
    sleep 5
    
    # Check container status
    local status=$($DOCKER_CMD ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" --filter "name=qasa-enhanced")
    echo "Container Status:"
    echo "$status"
}

# Verify deployment
verify_deployment() {
    print_status "Verifying deployment..."
    
    # Check if container is running
    local running=$($DOCKER_CMD ps --filter "name=qasa-enhanced" --format "{{.Names}}" || true)
    
    if [ -n "$running" ]; then
        print_success "Container is running: $running"
        
        # Test web interface
        print_status "Testing web interface accessibility..."
        
        # Wait a bit more for services to be fully ready
        sleep 3
        
        if curl -s -f http://localhost:8080/ > /dev/null; then
            print_success "✅ Web interface is accessible at http://localhost:8080"
        else
            print_warning "⚠️  Web interface not yet accessible (may need more time to start)"
        fi
        
        # Test API endpoint
        if curl -s -f http://localhost:8080/api/status > /dev/null; then
            print_success "✅ API endpoints are accessible"
        else
            print_warning "⚠️  API endpoints not yet accessible"
        fi
        
        # Show logs
        print_status "Recent container logs:"
        $DOCKER_CMD logs --tail 20 qasa-enhanced || true
        
    else
        print_error "Container is not running"
        print_status "Checking container logs for errors:"
        $DOCKER_CMD logs qasa-enhanced || true
        exit 1
    fi
}

# Show deployment information
show_info() {
    print_success "🎉 QaSa Enhanced Deployment Complete!"
    echo ""
    echo "📋 Access Information:"
    echo "  🌐 Web Interface: http://localhost:8080"
    echo "  📊 API Status:    http://localhost:8080/api/status"
    echo "  🔗 P2P Node:      localhost:9000"
    echo ""
    echo "🔧 Management Commands:"
    echo "  View logs:    $DOCKER_CMD logs -f qasa-enhanced"
    echo "  Stop:         $DOCKER_CMD stop qasa-enhanced"
    echo "  Restart:      $DOCKER_CMD restart qasa-enhanced"
    echo "  Remove:       $DOCKER_CMD rm -f qasa-enhanced"
    echo ""
    echo "✨ Enhanced Features Available:"
    echo "  • Modern dark/light theme system"
    echo "  • Real-time messaging with typing indicators"
    echo "  • Drag-and-drop file transfers"
    echo "  • Advanced peer discovery and search"
    echo "  • Complete encryption and security management"
    echo "  • Comprehensive notification system"
    echo "  • Responsive mobile-friendly design"
    echo ""
    echo "🧪 Test Suite Available:"
    echo "  Interactive tests: http://localhost:8082/test_web_features.html"
    echo "  (Run: python3 -m http.server 8082 to enable test suite)"
}

# Main execution
main() {
    echo "Starting QaSa Enhanced Deployment..."
    echo ""
    
    check_docker
    stop_existing_containers
    build_image
    deploy_container
    verify_deployment
    show_info
    
    print_success "🚀 Deployment completed successfully!"
}

# Handle script arguments
case "${1:-}" in
    "stop")
        check_docker
        stop_existing_containers
        print_success "QaSa containers stopped"
        ;;
    "build")
        check_docker
        build_image
        ;;
    "deploy")
        check_docker
        deploy_container
        verify_deployment
        show_info
        ;;
    "logs")
        check_docker
        $DOCKER_CMD logs -f qasa-enhanced
        ;;
    "status")
        check_docker
        $DOCKER_CMD ps --filter "name=qasa-enhanced"
        ;;
    *)
        main
        ;;
esac 