# QaSa Deployment Guide

This guide covers various deployment options for the QaSa secure chat application, from local development to production cloud deployments.

## Quick Start

The simplest way to deploy QaSa is using the provided deployment script:

```bash
# Development deployment with Docker
./deploy.sh

# Production deployment
./deploy.sh --mode production

# Native deployment without Docker
./deploy.sh --no-docker

# Build only (no deployment)
./deploy.sh --build-only
```

## Deployment Options

### 1. Docker Deployment (Recommended)

#### Prerequisites
- Docker (20.10+)
- Docker Compose (2.0+)

#### Development Deployment
```bash
# Clone and navigate to the repository
git clone <repository-url>
cd qasa

# Quick deployment
./deploy.sh

# Or manually with docker-compose
docker-compose up -d qasa-web
```

Access the application at `http://localhost:8080`

#### Production Deployment
```bash
# Deploy with nginx reverse proxy and SSL
./deploy.sh --mode production

# Or manually
docker-compose --profile production up -d
```

This will:
- Start the QaSa application
- Set up nginx reverse proxy with SSL termination
- Enable HTTPS on port 443
- Redirect HTTP traffic to HTTPS

### 2. Native Deployment

#### Prerequisites
- Go 1.22+
- Rust 1.75+
- CMake and build tools

#### Build and Run
```bash
# Build all components
./deploy.sh --no-docker --build-only

# Run manually
cd src/web
./qasa-web --port 9000 --web-port 8080
```

#### Production Service (systemd)
```bash
# Deploy as a system service
./deploy.sh --no-docker --mode production
```

### 3. Kubernetes Deployment

#### Prerequisites
- Kubernetes cluster (1.20+)
- kubectl configured
- nginx-ingress controller (optional)
- cert-manager (for SSL certificates)

#### Deploy to Kubernetes
```bash
# Apply Kubernetes manifests
kubectl apply -f src/web/k8s/

# Check deployment status
kubectl get pods -l app=qasa-web
kubectl get svc qasa-web-service
```

#### Configure Ingress (Optional)
Edit `src/web/k8s/ingress.yaml` and replace `your-domain.com` with your actual domain:

```bash
# Apply ingress configuration
kubectl apply -f src/web/k8s/ingress.yaml
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `QASA_WEB_PORT` | 8080 | Web interface port |
| `QASA_NETWORK_PORT` | 9000 | P2P network port |
| `QASA_ENABLE_MDNS` | true | Enable mDNS discovery |
| `QASA_ENABLE_DHT` | true | Enable DHT discovery |

### Docker Environment File

Create a `.env` file in the project root:

```env
QASA_WEB_PORT=8080
QASA_NETWORK_PORT=9000
QASA_MODE=production
```

### Configuration Files

The application uses configuration files stored in `~/.qasa/` directory:

- `keys/` - Cryptographic keys
- `config.yaml` - Application configuration
- `peers.json` - Known peers database

## SSL/TLS Configuration

### Development (Self-signed certificates)

The deployment script automatically generates self-signed certificates for development:

```bash
# Certificates will be created in ssl/ directory
./deploy.sh --mode production
```

### Production (Let's Encrypt)

For production deployments with real SSL certificates:

1. Install cert-manager in your Kubernetes cluster:
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
```

2. Create a ClusterIssuer for Let's Encrypt:
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: djwarfqasa@proton.me
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

3. Update the ingress.yaml with your domain name.

## Monitoring and Health Checks

### Health Check Endpoints

- `GET /api/status` - Application status
- `GET /api/peers` - Connected peers
- `WS /ws` - WebSocket connection test

### Docker Health Checks

Health checks are automatically configured in docker-compose.yml:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080"]
  interval: 30s
  timeout: 10s
  retries: 3
```

### Kubernetes Probes

Liveness and readiness probes are configured in the deployment:

```yaml
livenessProbe:
  httpGet:
    path: /api/status
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
```

## Scaling

### Docker Compose

To scale the application:

```bash
docker-compose up -d --scale qasa-web=3
```

### Kubernetes

To scale the deployment:

```bash
kubectl scale deployment qasa-web --replicas=5
```

## Security Considerations

### Production Checklist

- [ ] Use HTTPS with valid SSL certificates
- [ ] Configure firewall rules (ports 80, 443, 9000)
- [ ] Set up rate limiting (configured in nginx.conf)
- [ ] Regular security updates
- [ ] Monitor logs for suspicious activity
- [ ] Backup cryptographic keys regularly

### Network Security

- Port 8080: Web interface (should be behind reverse proxy in production)
- Port 9000: P2P network communication (needs to be accessible for peer discovery)
- Configure firewall to allow only necessary traffic

## Troubleshooting

### Common Issues

1. **Port already in use**
   ```bash
   # Check what's using the port
   sudo netstat -tulpn | grep :8080
   
   # Use different port
   ./deploy.sh --port 3000
   ```

2. **Docker build fails**
   ```bash
   # Check Docker logs
   docker-compose logs qasa-web
   
   # Rebuild without cache
   docker-compose build --no-cache
   ```

3. **Application not accessible**
   ```bash
   # Check container status
   docker-compose ps
   
   # Check logs
   docker-compose logs -f qasa-web
   ```

4. **SSL certificate issues**
   ```bash
   # Generate new self-signed certificates
   mkdir -p ssl
   openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes
   ```

### Log Files

- Docker: `docker-compose logs`
- Native: Application logs in `~/.qasa/logs/`
- Systemd: `journalctl -u qasa-web`

## Performance Tuning

### Docker Resource Limits

```yaml
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 512M
    reservations:
      cpus: '0.5'
      memory: 256M
```

### Kubernetes Resource Requests

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

## Backup and Recovery

### Backup Important Data

```bash
# Backup user keys and configuration
tar -czf qasa-backup-$(date +%Y%m%d).tar.gz ~/.qasa/

# For Docker volumes
docker run --rm -v qasa_qasa-data:/data -v $(pwd):/backup alpine tar czf /backup/qasa-data-backup.tar.gz /data
```

### Restore from Backup

```bash
# Restore user configuration
tar -xzf qasa-backup-YYYYMMDD.tar.gz -C ~/

# For Docker volumes
docker run --rm -v qasa_qasa-data:/data -v $(pwd):/backup alpine tar xzf /backup/qasa-data-backup.tar.gz -C /
```

## Support

For deployment issues:

1. Check the logs for error messages
2. Verify all prerequisites are installed
3. Ensure ports are not blocked by firewall
4. Check the GitHub issues page for known problems
5. Create a new issue with deployment details and error logs 