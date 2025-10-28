# Hanzo Gateway - AI Assistant Knowledge Base

> **Comprehensive documentation for AI assistants working with the Hanzo Gateway project**

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Repository Structure](#repository-structure)
4. [Environment Configuration](#environment-configuration)
5. [Building](#building)
6. [Testing](#testing)
7. [Docker](#docker)
8. [CI/CD Pipeline](#cicd-pipeline)
9. [Deployment](#deployment)
10. [Versioning and Releases](#versioning-and-releases)
11. [Development Workflow](#development-workflow)
12. [Troubleshooting](#troubleshooting)

---

## Project Overview

**Hanzo Gateway** is a production-ready multi-provider AI inference platform for the Hanzo ecosystem. It provides secure, cost-effective AI inference across multiple providers including DigitalOcean, OpenAI, and Anthropic Claude with built-in rate limiting, cost controls, and device authentication.

### Key Features

- **Multi-Provider Support**: DigitalOcean Gradient AI, OpenAI, Anthropic Claude
- **Pure Environment Variable Configuration**: No config files required
- **Production-Ready**: Docker-based deployment with health checks and monitoring
- **Security**: Rate limiting, cost controls, device authentication
- **Cost-Effective**: Default to affordable providers (DigitalOcean Qwen3-32B)
- **Semantic Versioning**: Automated releases with GitHub Actions

### Technology Stack

- **Backend**: Rust (Hanzo Node), Node.js (Gateway Services)
- **Container**: Docker with multi-stage builds
- **CI/CD**: GitHub Actions
- **Package Manager**: npm
- **Docker Registry**: Docker Hub (hanzoai/gateway)

---

## Architecture

```
┌─────────────────┐
│ hanzo-desktop   │
│   (client)      │
└────────┬────────┘
         │
         v
┌─────────────────┐     ┌──────────────────┐
│  Hanzo Gateway  │────▶│  Gateway Services│
│  (port 9550)    │     │  (ports 3001-3)  │
│                 │     │                  │
│  - Rust         │     │  - Node.js       │
│  - Blockchain   │     │  - Rate limiting │
│  - AI agents    │     │  - Cost control  │
└─────────────────┘     └────────┬─────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
         v                       v                       v
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ DigitalOcean    │   │    OpenAI       │   │   Anthropic     │
│ (Qwen3-32B)     │   │   (GPT-4o)      │   │ (Claude 3.5)    │
│ Default         │   │   Premium       │   │  Reasoning      │
└─────────────────┘   └─────────────────┘   └─────────────────┘
```

### Components

1. **Hanzo Node** (`docker/`)
   - Rust-based core inference engine
   - Multi-provider AI agent support
   - Runs on port 9550
   - Health check endpoint: `/v2/health_check`

2. **Gateway Services** (`gateway/`)
   - Node.js API proxy
   - Rate limiting and cost tracking
   - Runs on ports 3001-3002
   - Optional add-on for additional features

---

## Repository Structure

```
hanzo-gateway/
├── .github/
│   └── workflows/
│       ├── ci.yml                    # CI/CD pipeline (tests)
│       ├── build-and-push.yml        # Docker image builds
│       └── release.yml               # Semantic versioning releases
├── docker/
│   ├── Dockerfile                    # Multi-stage Docker build
│   ├── run_node.sh                   # Entrypoint script
│   └── compose.yml                   # Docker Compose config
├── gateway/
│   ├── test/                         # Gateway service tests
│   ├── package.json                  # Node.js dependencies
│   └── test-server.js                # Test server
├── .env.example                      # Environment variables template
├── README.md                         # User documentation
├── LLM.md                            # This file
└── CONTRIBUTING.md                   # Contribution guidelines
```

### Critical Files

- **`docker/Dockerfile`**: Multi-stage build that compiles Hanzo Node from Rust source and creates production image
- **`docker/run_node.sh`**: Entrypoint script with pure env var configuration
- **`docker/compose.yml`**: Docker Compose configuration for local development
- **`.env.example`**: Template with all available environment variables

---

## Environment Configuration

### Pure Environment Variable Configuration

The Hanzo Gateway is configured **entirely through environment variables**. No configuration files are required at runtime.

### Key Environment Variables

```bash
# Network Configuration
NODE_API_IP=0.0.0.0                     # API bind address
NODE_API_PORT=9550                      # HTTP API port
NODE_WS_PORT=9551                       # WebSocket port
NODE_PORT=9552                          # P2P port
NODE_HTTPS_PORT=9553                    # HTTPS API port

# Identity and Security
IDENTITY_SECRET_KEY=                    # Required: Node identity key
ENCRYPTION_SECRET_KEY=                  # Required: Encryption key
GLOBAL_IDENTITY_NAME=@@my_local_ai.sep-hanzo

# AI Provider Configuration
INITIAL_AGENT_NAMES=do_qwen32b          # Comma-separated agent names
INITIAL_AGENT_URLS=https://inference.do-ai.run
INITIAL_AGENT_MODELS=openai:alibaba-qwen3-32b
INITIAL_AGENT_API_KEYS=                 # Required: API keys

# Logging
RUST_LOG=debug,error,info
LOG_SIMPLE=true
LOG_ALL=1
```

### Configuration Files

- **`.env.example`**: Complete template with all variables and examples
- Copy to `.env` for local development
- In production, set environment variables directly (Kubernetes, Docker, etc.)

---

## Building

### Prerequisites

- Docker 20.10+
- Docker Buildx (for multi-platform builds)
- Access to hanzoai/node repository (for source code)

### Build Process

The Dockerfile expects the Hanzo Node source code to be in the build context:

#### 1. Manual Local Build

```bash
# Clone repositories
git clone https://github.com/hanzoai/node.git hanzo-node
git clone https://github.com/hanzoai/gateway.git hanzo-gateway

# Build debug version
docker build \
  --build-arg BUILD_TYPE=debug \
  --build-arg HANZO_VERSION=$(git -C hanzo-node describe --tags) \
  -f hanzo-gateway/docker/Dockerfile \
  -t hanzoai/gateway:dev \
  hanzo-node

# Build release version
docker build \
  --build-arg BUILD_TYPE=release \
  --build-arg HANZO_VERSION=1.0.0 \
  -f hanzo-gateway/docker/Dockerfile \
  -t hanzoai/gateway:1.0.0 \
  hanzo-node
```

#### 2. Multi-Platform Build

```bash
# Create builder
docker buildx create --name hanzo-builder --use

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg BUILD_TYPE=release \
  --build-arg HANZO_VERSION=1.0.0 \
  -f hanzo-gateway/docker/Dockerfile \
  -t hanzoai/gateway:1.0.0 \
  --push \
  hanzo-node
```

### Build Arguments

- `BUILD_TYPE`: `release` or `debug` (default: `debug`)
- `HANZO_VERSION`: Semantic version (e.g., `1.0.0`)
- `BUILD_DATE`: ISO 8601 timestamp
- `VCS_REF`: Git commit SHA

---

## Testing

### Test Structure

```
gateway/
└── test/
    └── api.test.js                   # API integration tests
```

### Running Tests Locally

```bash
# Install dependencies
cd gateway
npm install

# Set environment variables
export DIGITALOCEAN_API_KEY=sk-do-YOUR_KEY

# Run tests
npm test

# Run specific test
npm run test:api
```

### Test Scripts

- `npm test`: Run all tests
- `npm run test:api`: Run API tests
- `npm run test:integration`: Run integration tests
- `npm start`: Start test server

### CI Testing

Tests run automatically on:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`

Test workflow: `.github/workflows/ci.yml`

---

## Docker

### Docker Image

**Image**: `hanzoai/gateway`
**Registry**: Docker Hub

### Image Tags

- `latest`: Latest stable release from main branch
- `v1.0.0`: Specific version tags
- `1.0`: Major.minor tags
- `1`: Major version tags
- `main-abc1234`: Branch-specific builds
- `develop`: Development branch builds

### Running the Container

```bash
# Pull latest image
docker pull hanzoai/gateway:latest

# Run with environment variables
docker run -d \
  --name hanzo-gateway \
  -p 9550:9550 \
  -p 9551:9551 \
  -e IDENTITY_SECRET_KEY=your-secret-key \
  -e ENCRYPTION_SECRET_KEY=your-encryption-key \
  -e INITIAL_AGENT_API_KEYS=sk-do-your-key \
  -v hanzo-data:/app/hanzo-storage \
  hanzoai/gateway:latest

# Check health
curl http://localhost:9550/v2/health_check

# View logs
docker logs -f hanzo-gateway
```

### Docker Compose

```bash
# Copy environment template
cp .env.example .env
# Edit .env with your API keys

# Start services
docker compose up -d

# View logs
docker compose logs -f hanzo-node

# Stop services
docker compose down
```

### Health Checks

The container includes a built-in health check:
- **Endpoint**: `http://localhost:9550/v2/health_check`
- **Interval**: 30 seconds
- **Timeout**: 10 seconds
- **Start Period**: 40 seconds
- **Retries**: 3

---

## CI/CD Pipeline

### Workflows

1. **CI Pipeline** (`.github/workflows/ci.yml`)
   - Runs on: Push, Pull Request
   - Tests gateway services
   - Security scanning
   - Integration tests

2. **Build and Push** (`.github/workflows/build-and-push.yml`)
   - Runs on: Push to main/develop, Tags
   - Builds Rust node from source
   - Builds Docker images (amd64, arm64)
   - Pushes to Docker Hub
   - Tests built images

3. **Release** (`.github/workflows/release.yml`)
   - Runs on: Version tags (v*)
   - Creates GitHub releases
   - Builds platform-specific binaries
   - Generates changelog
   - Updates latest tag

### GitHub Secrets Required

```
DOCKERHUB_USERNAME          # Docker Hub username
DOCKERHUB_TOKEN             # Docker Hub access token
GH_PAT                      # GitHub Personal Access Token (for private repos)
DIGITALOCEAN_API_KEY        # For testing
JWT_SECRET                  # For testing
```

### Workflow Triggers

```yaml
# CI runs on
- push: main, develop
- pull_request: main, develop

# Build and Push runs on
- push: main, develop
- tags: v*
- workflow_dispatch (manual)

# Release runs on
- tags: v*
- workflow_dispatch (manual)
```

---

## Deployment

### Production Deployment Options

#### 1. Docker Compose (Simple)

```bash
# On production server
git clone https://github.com/hanzoai/gateway.git
cd gateway

# Configure environment
cp .env.example .env
nano .env  # Set production values

# Start services
docker compose up -d

# Monitor
docker compose logs -f
```

#### 2. Kubernetes (Scalable)

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hanzo-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: hanzo-gateway
  template:
    metadata:
      labels:
        app: hanzo-gateway
    spec:
      containers:
      - name: gateway
        image: hanzoai/gateway:latest
        ports:
        - containerPort: 9550
        env:
        - name: NODE_API_PORT
          value: "9550"
        - name: IDENTITY_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: hanzo-secrets
              key: identity-key
        - name: INITIAL_AGENT_API_KEYS
          valueFrom:
            secretKeyRef:
              name: hanzo-secrets
              key: api-keys
        livenessProbe:
          httpGet:
            path: /v2/health_check
            port: 9550
          initialDelaySeconds: 40
          periodSeconds: 30
        volumeMounts:
        - name: data
          mountPath: /app/hanzo-storage
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: hanzo-data
```

#### 3. Cloud Providers

**DigitalOcean Droplet**:
```bash
# Create droplet with Docker
doctl compute droplet create hanzo-gateway \
  --size s-2vcpu-4gb \
  --image docker-20-04 \
  --region nyc1

# SSH and deploy
ssh root@droplet-ip
docker run -d --restart unless-stopped \
  -p 9550:9550 \
  -e IDENTITY_SECRET_KEY=... \
  hanzoai/gateway:latest
```

**AWS ECS**: Use Task Definition with container image `hanzoai/gateway:latest`

**Google Cloud Run**: Deploy with `gcloud run deploy` using the Docker image

### SSL/TLS Configuration

For production, use a reverse proxy:

```nginx
# nginx.conf
server {
    listen 443 ssl;
    server_name gateway.hanzo.ai;

    ssl_certificate /etc/letsencrypt/live/gateway.hanzo.ai/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/gateway.hanzo.ai/privkey.pem;

    location / {
        proxy_pass http://localhost:9550;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Versioning and Releases

### Semantic Versioning

The project follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality, backwards-compatible
- **PATCH**: Bug fixes, backwards-compatible

### Creating a Release

#### Automatic (Recommended)

```bash
# Tag and push
git tag -a v1.2.0 -m "Release version 1.2.0"
git push origin v1.2.0

# GitHub Actions will:
# 1. Build Docker images
# 2. Push to Docker Hub
# 3. Create GitHub release
# 4. Build platform binaries
# 5. Generate changelog
```

#### Manual Trigger

```bash
# Via GitHub UI:
# 1. Go to Actions → Release
# 2. Click "Run workflow"
# 3. Enter version (e.g., 1.2.0)
# 4. Select if pre-release
# 5. Run
```

### Release Artifacts

Each release includes:

1. **Docker Images**:
   - `hanzoai/gateway:1.2.0`
   - `hanzoai/gateway:1.2`
   - `hanzoai/gateway:1`
   - `hanzoai/gateway:latest`

2. **Binary Archives**:
   - `hanzo-gateway-linux-amd64-v1.2.0.tar.gz`
   - `hanzo-gateway-linux-arm64-v1.2.0.tar.gz`
   - `hanzo-gateway-macos-amd64-v1.2.0.tar.gz`
   - `hanzo-gateway-macos-arm64-v1.2.0.tar.gz`

3. **Release Notes**:
   - Automatically generated changelog
   - Docker pull commands
   - Asset links

---

## Development Workflow

### Setting Up Development Environment

```bash
# Clone repositories
git clone https://github.com/hanzoai/gateway.git
cd gateway

# Gateway services
cd gateway
npm install
cp .env.example .env
# Edit .env with test API keys

# Run tests
npm test

# Start development server
npm run dev
```

### Making Changes

1. **Create Branch**
   ```bash
   git checkout -b feature/your-feature
   ```

2. **Make Changes**
   - Update code
   - Add tests
   - Update documentation

3. **Test Locally**
   ```bash
   cd gateway
   npm test
   ```

4. **Commit and Push**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   git push origin feature/your-feature
   ```

5. **Create Pull Request**
   - Open PR on GitHub
   - CI runs automatically
   - Wait for review

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: resolve bug in API
docs: update README
chore: update dependencies
test: add integration tests
ci: update workflow
refactor: improve code structure
```

### Code Review Process

1. Automated checks must pass:
   - Tests
   - Linting
   - Security scan

2. Manual review by maintainer

3. Squash and merge to main

---

## Troubleshooting

### Build Issues

**Problem**: Docker build fails
```bash
# Solution: Check build context
docker build \
  -f hanzo-gateway/docker/Dockerfile \
  hanzo-node  # Must be node repo directory

# Verify source is present
ls hanzo-node/Cargo.toml  # Should exist
```

**Problem**: Multi-platform build fails
```bash
# Solution: Set up buildx
docker buildx create --name hanzo-builder --use
docker buildx inspect --bootstrap
```

### Runtime Issues

**Problem**: Container fails health check
```bash
# Check logs
docker logs hanzo-gateway

# Verify ports
docker port hanzo-gateway

# Test manually
docker exec hanzo-gateway curl localhost:9550/v2/health_check
```

**Problem**: Missing API keys
```bash
# Verify environment variables
docker exec hanzo-gateway env | grep INITIAL_AGENT_API_KEYS

# Restart with correct values
docker stop hanzo-gateway
docker run -d -e INITIAL_AGENT_API_KEYS=sk-your-key ...
```

### CI/CD Issues

**Problem**: CI tests failing
```bash
# Check GitHub Actions logs
# Common fixes:
# 1. Update secrets in GitHub repo settings
# 2. Ensure package-lock.json is committed
# 3. Check working-directory in workflow
```

**Problem**: Docker push fails
```bash
# Verify Docker Hub credentials
# Settings → Secrets → DOCKERHUB_USERNAME, DOCKERHUB_TOKEN

# Check token permissions (Read, Write, Delete)
```

### Test Issues

**Problem**: Tests timeout
```bash
# Increase sleep time
# In .github/workflows/ci.yml
sleep 10  # Instead of 3
```

**Problem**: API key errors
```bash
# Set test API key
export DIGITALOCEAN_API_KEY=sk-do-your-test-key
npm test
```

---

## Additional Resources

### Documentation

- **README.md**: User-facing documentation
- **CONTRIBUTING.md**: Contribution guidelines
- **PROVIDERS_SETUP.md**: Multi-provider AI configuration
- **DOCKER.md**: Cloud deployment guide

### Links

- **GitHub**: https://github.com/hanzoai/gateway
- **Docker Hub**: https://hub.docker.com/r/hanzoai/gateway
- **Website**: https://hanzo.ai
- **Documentation**: https://docs.hanzo.ai/gateway

### Support

- **Issues**: https://github.com/hanzoai/gateway/issues
- **Email**: support@hanzo.ai
- **Discord**: https://discord.gg/hanzo

---

## Quick Reference

### Common Commands

```bash
# Build image
docker build -f hanzo-gateway/docker/Dockerfile -t hanzoai/gateway:dev hanzo-node

# Run container
docker run -d -p 9550:9550 -e INITIAL_AGENT_API_KEYS=key hanzoai/gateway:latest

# Run tests
cd gateway && npm test

# Create release
git tag v1.0.0 && git push origin v1.0.0

# Deploy with compose
docker compose up -d

# View logs
docker logs -f hanzo-gateway

# Health check
curl http://localhost:9550/v2/health_check
```

### Environment Variables Summary

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NODE_API_PORT` | No | 9550 | HTTP API port |
| `IDENTITY_SECRET_KEY` | Yes | - | Node identity key |
| `ENCRYPTION_SECRET_KEY` | Yes | - | Encryption key |
| `INITIAL_AGENT_API_KEYS` | Yes | - | Provider API keys |
| `INITIAL_AGENT_NAMES` | No | do_qwen32b | Agent names |
| `INITIAL_AGENT_URLS` | No | https://inference.do-ai.run | Provider URLs |
| `INITIAL_AGENT_MODELS` | No | openai:alibaba-qwen3-32b | Model identifiers |

---

**Last Updated**: 2025-01-28
**Version**: 1.0.0
**Maintainer**: Hanzo AI Team
