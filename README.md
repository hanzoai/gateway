# Hanzo Gateway

High-performance API gateway for Hanzo AI services. Routes 147+ API endpoints across production clusters with rate limiting, authentication forwarding, CORS, circuit breakers, and telemetry -- all driven by declarative JSON configuration.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/hanzoai/gateway/blob/main/LICENSE)

## Overview

Hanzo Gateway is the unified API entry point for all Hanzo and Lux network traffic. It sits behind [Hanzo Ingress](https://github.com/hanzoai/ingress) (L7 reverse proxy) and routes requests to internal services with per-endpoint rate limiting, header forwarding, and circuit breaker protection.

Two independent gateway instances serve production clusters:

| Cluster | Domain | Endpoints | Rate Limit (global) | Rate Limit (per IP) |
|---------|--------|-----------|---------------------|---------------------|
| **hanzo-k8s** | `api.hanzo.ai` | 133 | 5,000 req/s | 100 req/s |
| **lux-k8s** | `api.lux.network` | 14 | 1,000 req/s | 100 req/s |

## Architecture

```
                    Internet
                       |
              +--------+--------+
              |                 |
     Cloudflare (hanzo)   DO LB (lux)
              |                 |
     +--------+--------+  +----+----+
     | Hanzo Ingress    |  | Lux LB  |
     | (L7 TLS/routing) |  |         |
     +--------+---------+  +----+----+
              |                 |
     +--------+---------+  +---+--------+
     | Hanzo Gateway    |  | Lux Gateway |
     | 133 endpoints    |  | 14 endpoints|
     +---+----+----+----+  +---+---+----+
         |    |    |            |   |
      Cloud  IAM  Commerce   Luxd  Luxd
      API         API       (main) (test)
```

### Hanzo Cluster Routes (`api.hanzo.ai`)

| Path | Backend | Description |
|------|---------|-------------|
| `/v1/chat/completions` | cloud-api:8000 | LLM chat completions |
| `/v1/completions` | cloud-api:8000 | Text completions |
| `/v1/models` | cloud-api:8000 | Model listing |
| `/v1/embeddings` | cloud-api:8000 | Embedding generation |
| `/v1/*` | cloud-api:8000 | All OpenAI-compatible API routes |
| `/commerce/*` | commerce:8001 | Commerce API |
| `/auth/*` | iam:8000 | IAM / authentication |

### Lux Cluster Routes (`api.lux.network`)

| Path | Backend | Description |
|------|---------|-------------|
| `/ext/bc/C/rpc` | luxd:9630 | Mainnet EVM RPC |
| `/mainnet/ext/bc/C/rpc` | luxd:9630 | Mainnet EVM RPC (explicit) |
| `/testnet/ext/bc/C/rpc` | luxd:9640 | Testnet EVM RPC |
| `/devnet/ext/bc/C/rpc` | luxd:9650 | Devnet EVM RPC |

## Features

- **Declarative JSON config** -- all routing, rate limiting, and backend definitions in a single file per cluster
- **Per-endpoint rate limiting** -- global and per-IP limits with configurable windows
- **Circuit breakers** -- automatic backend failure isolation
- **Header forwarding** -- full passthrough of auth headers, content types, and custom headers
- **CORS support** -- configurable cross-origin policies
- **Telemetry** -- structured logging with `[GATEWAY]` prefix, Prometheus-compatible metrics
- **Health checks** -- `GET /__health` on port 8080
- **Zero-downtime deploys** -- ConfigMap-based config with rolling restart
- **Multi-cluster** -- independent configs and deployments per cluster

## Quick Start

### Build from Source

```bash
# Build gateway binary
make build

# Build ingress sidecar binary
make build-ingress

# Run tests
make test

# Validate all configs
make validate
```

### Run Locally

```bash
# Run with hanzo config
./gateway run -c configs/hanzo/gateway.json

# Run with lux config
./gateway run -c configs/lux/gateway.json
```

### Docker

```bash
# Build Docker image (hanzo config baked in)
make docker-hanzo

# Build Docker image (lux config baked in)
make docker-lux

# Run
docker run -p 8080:8080 ghcr.io/hanzoai/gateway:latest
```

## Kubernetes Deployment

### Deploy to Hanzo Cluster

```bash
# Apply config and restart pods
make deploy-hanzo

# Check status
make status

# Tail logs
make logs-hanzo
```

### Deploy to Lux Cluster

```bash
# Apply config and restart pods
make deploy-lux

# Tail logs
make logs-lux
```

### Deploy to Both

```bash
make deploy
```

### Infrastructure Details

| Property | Hanzo Cluster | Lux Cluster |
|----------|---------------|-------------|
| **Image** | `ghcr.io/hanzoai/gateway:latest` | `ghcr.io/hanzoai/gateway:lux-latest` |
| **Replicas** | 2 | 2 |
| **Service type** | ClusterIP (behind Ingress) | LoadBalancer |
| **Namespace** | `hanzo` | `lux-gateway` |
| **K8s context** | `do-sfo3-hanzo-k8s` | `do-sfo3-lux-k8s` |
| **Health check** | `GET /__health` :8080 | `GET /__health` :8080 |

### K8s Manifests

```
k8s/
  hanzo/
    deployment.yaml     # Gateway deployment (2 replicas)
    service.yaml        # ClusterIP service
    ingress.yaml        # Ingress resource for api.hanzo.ai
  lux/
    deployment.yaml     # Gateway deployment (2 replicas)
    service.yaml        # LoadBalancer service
```

## Configuration

All routing is defined in JSON configuration files. Each cluster has its own config.

### Editing Routes

1. Edit the appropriate config file:
   ```bash
   # Hanzo API routes
   $EDITOR configs/hanzo/gateway.json

   # Lux blockchain routes
   $EDITOR configs/lux/gateway.json
   ```

2. Validate the config:
   ```bash
   make validate
   ```

3. Deploy:
   ```bash
   make deploy-hanzo   # or deploy-lux
   ```

The Makefile creates a ConfigMap from the JSON file and triggers a rolling restart.

### Config Structure

```json
{
  "version": 3,
  "name": "Hanzo API Gateway",
  "port": 8080,
  "timeout": "120s",
  "extra_config": {
    "qos/ratelimit/router": {
      "max_rate": 5000,
      "client_max_rate": 100,
      "strategy": "ip"
    },
    "telemetry/logging": {
      "level": "INFO",
      "prefix": "[GATEWAY]",
      "stdout": true
    }
  },
  "endpoints": [
    {
      "endpoint": "/v1/chat/completions",
      "method": "POST",
      "input_headers": ["*"],
      "output_encoding": "no-op",
      "backend": [{
        "url_pattern": "/api/chat/completions",
        "host": ["http://cloud-api.hanzo.svc.cluster.local:8000"],
        "encoding": "no-op"
      }]
    }
  ]
}
```

### Per-Endpoint Rate Limiting

Each endpoint can override the global rate limit:

```json
{
  "extra_config": {
    "qos/ratelimit/router": {
      "max_rate": 5000,
      "client_max_rate": 100,
      "strategy": "ip",
      "every": "1m"
    }
  }
}
```

## Repository Structure

```
configs/
  hanzo/
    gateway.json        # Hanzo API Gateway config (133 endpoints)
    ingress.json        # Hanzo Ingress sidecar config
  lux/
    gateway.json        # Lux API Gateway config (14 endpoints)
k8s/
  hanzo/                # K8s manifests for hanzo-k8s cluster
  lux/                  # K8s manifests for lux-k8s cluster
cmd/
  gateway/              # Gateway binary entry point
  ingress/              # Ingress sidecar binary entry point
tests/                  # Integration tests
Dockerfile              # Multi-stage build (Go build + Alpine runtime)
Makefile                # Build, test, validate, deploy commands
```

## DNS

| Domain | Path | Target |
|--------|------|--------|
| `*.hanzo.ai` | Cloudflare | hanzo-k8s LB (`24.199.76.156`) -> Ingress -> Gateway |
| `*.lux.network` | DO LB | lux-k8s LB (`134.199.141.71`) -> Gateway |

## Hanzo Infrastructure Stack

Hanzo Gateway is one of four products in the Hanzo AI infrastructure stack:

| Product | Role | Repository |
|---------|------|------------|
| [**Hanzo Ingress**](https://github.com/hanzoai/ingress) | L7 reverse proxy, TLS termination, load balancing | `hanzoai/ingress` |
| [**Hanzo Gateway**](https://github.com/hanzoai/gateway) | API gateway, rate limiting, endpoint routing | `hanzoai/gateway` |
| [**Hanzo Engine**](https://github.com/hanzoai/engine) | GPU inference engine, model serving | `hanzoai/engine` |
| [**Hanzo Edge**](https://github.com/hanzoai/edge) | On-device inference runtime (mobile, web, embedded) | `hanzoai/edge` |

```
Internet -> Ingress (TLS/L7) -> Gateway (API routing) -> Engine (inference) / Cloud API / Services
                                                          Edge (on-device, client-side)
```

## License

Apache 2.0 -- see [LICENSE](LICENSE).
