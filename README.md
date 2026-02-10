# Hanzo Gateway

KrakenD-based API gateway for Hanzo AI and Lux Network clusters.

## Architecture

Two independent KrakenD instances serve as the entry point for all API traffic:

**Hanzo cluster** (`api.hanzo.ai` / `*.hanzo.ai`):
- `/v1/*` → LLM proxy (gateway service, port 4000)
- `/commerce/*` → Commerce API (port 8001)
- `/auth/*` → IAM / Casdoor (port 8000)
- Rate limit: 5000 req/s global, 500 req/s per IP

**Lux cluster** (`api.lux.network` / `*.lux.network`):
- `/ext/bc/C/rpc` → Mainnet EVM RPC (luxd, port 9630)
- `/mainnet/ext/bc/C/rpc` → Mainnet EVM RPC
- `/testnet/ext/bc/C/rpc` → Testnet EVM RPC (port 9640)
- `/devnet/ext/bc/C/rpc` → Devnet EVM RPC (port 9650)
- Rate limit: 1000 req/s global, 100 req/s per IP

## Quick Start

```bash
# Validate configs
make validate

# Deploy to hanzo-k8s
make deploy-hanzo

# Deploy to lux-k8s
make deploy-lux

# Deploy both
make deploy

# Check status
make status
```

## Structure

```
configs/
  hanzo/krakend.json    # Hanzo API Gateway config
  lux/krakend.json      # Lux API Gateway config
k8s/
  hanzo/                # k8s manifests for hanzo cluster
  lux/                  # k8s manifests for lux cluster
Dockerfile              # KrakenD image with baked config
Makefile                # Build and deploy commands
```

## Editing Routes

1. Edit the appropriate `configs/<cluster>/krakend.json`
2. Validate: `make validate`
3. Deploy: `make deploy-hanzo` or `make deploy-lux`

The Makefile creates a ConfigMap from the JSON file and restarts the KrakenD pods.

## Infrastructure

- **Image**: `devopsfaith/krakend:2.5`
- **Hanzo**: 2 replicas, ClusterIP service (behind Cloudflare proxy)
- **Lux**: 2 replicas, LoadBalancer service (DO LB → `134.199.141.71`)
- **Health check**: `GET /__health` on port 8080

## DNS

All `*.hanzo.ai` traffic routes through Cloudflare → hanzo-k8s LB (`24.199.76.156`) → KrakenD.
All `*.lux.network` traffic routes through the lux-api-gateway LB (`134.199.141.71`) → KrakenD.
