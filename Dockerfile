# Multi-stage Dockerfile for QaSa Secure Chat Application
# Stage 1: Build Rust crypto module
FROM rustlang/rust:nightly-slim as crypto-builder

# Install required dependencies for liboqs and the crypto module
RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/crypto
COPY src/crypto/ .

# Remove benchmark configuration and regenerate lock file
RUN sed -i '/\[\[bench\]\]/,/harness = false/d' Cargo.toml && \
    rm -f Cargo.lock && \
    cargo generate-lockfile

# Build the crypto module
RUN cargo build --release --lib

# Stage 2: Build Go application  
FROM golang:1.23-bookworm as go-builder

# Install build dependencies for CGO
RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy go modules
COPY src/go.mod src/go.sum ./
COPY src/network/go.mod src/network/go.sum ./src/network/
COPY src/web/go.mod src/web/go.sum ./src/web/

# Download dependencies
RUN cd src/network && go mod download
RUN cd src/web && go mod download

# Copy source code
COPY src/ ./src/

# Copy the built crypto library from the first stage
COPY --from=crypto-builder /app/crypto/target/release/libqasa_crypto.so /usr/local/lib/
RUN ldconfig

# Build the network module
WORKDIR /app/src/network
RUN CGO_ENABLED=1 CGO_LDFLAGS="-L/usr/local/lib -lssl -lcrypto" go build -o qasa-network main.go

# Build the web module
WORKDIR /app/src/web
RUN CGO_ENABLED=1 CGO_LDFLAGS="-L/usr/local/lib -lssl -lcrypto" go build -o qasa-web main.go

# Stage 3: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create qasa user
RUN useradd -m -s /bin/bash qasa

# Copy the built binaries and libraries
COPY --from=crypto-builder /app/crypto/target/release/libqasa_crypto.so /usr/local/lib/
COPY --from=go-builder /app/src/network/qasa-network /usr/local/bin/
COPY --from=go-builder /app/src/web/qasa-web /usr/local/bin/

# Copy web static files
COPY --from=go-builder /app/src/web/*.html /app/web/
COPY --from=go-builder /app/src/web/*.css /app/web/
COPY --from=go-builder /app/src/web/*.js /app/web/
COPY --from=go-builder /app/src/web/*.svg /app/web/
COPY --from=go-builder /app/src/web/static/ /app/web/static/

# Update library cache
RUN ldconfig

# Set proper permissions
RUN chmod +x /usr/local/bin/qasa-network /usr/local/bin/qasa-web
RUN chown -R qasa:qasa /app

# Switch to qasa user
USER qasa

# Create config directory
RUN mkdir -p /home/qasa/.qasa

# Expose ports
EXPOSE 8080 9000

# Default command to run the web interface
CMD ["qasa-web", "--port", "9000", "--web-port", "8080"] 