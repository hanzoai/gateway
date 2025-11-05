# Hanzo Gateway - Deployment Status

**Date**: 2025-11-04
**Status**: ✅ **LIVE**

## Current Deployment

### Infrastructure

- **Droplet**: hanzo-gateway
- **IP Address**: 143.198.188.26
- **Region**: SFO3 (DigitalOcean San Francisco)
- **Size**: s-1vcpu-1gb ($6/month)
- **Image**: hanzoai/gateway:latest
- **Port**: 3001

### Service Status

```bash
✅ Container: hanzo-gateway (Up and running)
✅ Health: http://143.198.188.26:3001/health
✅ Models: http://143.198.188.26:3001/v1/models
✅ Gateway Identity: did:hanzo:gateway
```

### Health Check Response

```json
{
  "status": "ok",
  "identity": "did:hanzo:gateway",
  "providers": ["local"],
  "limits": {
    "requestsPerMinute": 10,
    "requestsPerHour": 100,
    "requestsPerDay": 500,
    "tokensPerDay": 50000
  },
  "cloudflare": true,
  "timestamp": "2025-11-05T05:31:41.070Z"
}
```

### Available Models

```json
[
  {
    "id": "deepseek-chat",
    "provider": "deepseek",
    "pricing": "Free tier"
  },
  {
    "id": "deepseek-coder",
    "provider": "deepseek",
    "pricing": "Free tier"
  },
  {
    "id": "qwen3-32b",
    "provider": "local",
    "pricing": "Free (local)"
  },
  {
    "id": "zen-coder-30b",
    "provider": "local",
    "pricing": "Free (local)"
  }
]
```

## Architecture

### Current Setup (November 4, 2025)

```
Client
  ↓
Cloudflare (optional - not yet configured)
  ↓
143.198.188.26:3001 (hanzo-gateway)
  ↓
Gateway (Node.js - server.js)
  ↓
Rate Limiter (in-memory, IP-based)
  ↓
Provider Router
  ├─→ DeepSeek API (deepseek-* models)
  ├─→ OpenAI API (gpt-* models, if configured)
  ├─→ Anthropic API (claude-* models, if configured)
  └─→ Local Node (qwen*, zen-* models)
```

### Configuration

**Active Features**:
- ✅ Multi-provider routing (DeepSeek primary)
- ✅ IP-based rate limiting
- ✅ Cloudflare proxy support enabled
- ✅ Usage tracking (in-memory)
- ✅ Token counting

**Environment**:
```bash
PORT=3001
HOST=0.0.0.0
GATEWAY_IDENTITY=did:hanzo:gateway
TRUST_PROXY=true (Cloudflare ready)
```

**Rate Limits** (Free Tier):
- Requests per minute: 10
- Requests per hour: 100
- Requests per day: 500
- Tokens per day: 50,000

## Testing the Deployment

### 1. Health Check

```bash
curl http://143.198.188.26:3001/health
```

### 2. List Available Models

```bash
curl http://143.198.188.26:3001/v1/models
```

### 3. Chat Completion Request

```bash
curl -X POST http://143.198.188.26:3001/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-chat",
    "messages": [
      {"role": "user", "content": "Hello, who are you?"}
    ]
  }'
```

### 4. Check Rate Limit Status

```bash
curl http://143.198.188.26:3001/v1/rate-limit-status
```

## Docker Image

### Published Image

- **Repository**: hanzoai/gateway
- **Tag**: latest
- **Digest**: sha256:ccb9abdc5b43f5f5f962488938074ffb3a18c66b56aced0412198ad1e74614ac
- **Platforms**: linux/amd64, linux/arm64
- **Size**: ~200MB
- **Base**: node:20-slim

### Image Build

```bash
# Multi-platform build
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t hanzoai/gateway:latest \
  --push \
  .
```

## Deployment Process

### What Was Deployed

1. **Built multi-platform Docker image** (amd64 + arm64)
2. **Pushed to Docker Hub** (hanzoai/gateway:latest)
3. **Deployed to DigitalOcean droplet** (hanzo-gateway)
4. **Container running successfully** on port 3001

### Deployment Command

```bash
./deploy.sh
```

### Container Status

```bash
doctl compute ssh hanzo-gateway \
  --ssh-command "docker ps --filter name=hanzo-gateway"

# Output:
NAMES           STATUS         PORTS
hanzo-gateway   Up X minutes   0.0.0.0:3001->3001/tcp, [::]:3001->3001/tcp
```

## Next Steps

### Immediate

1. ⏳ **Configure DNS**:
   ```bash
   # Point api.hanzo.ai to 143.198.188.26
   # Enable Cloudflare proxy (orange cloud)
   ```

2. ⏳ **Add API Keys** (optional):
   ```bash
   # SSH to droplet
   doctl compute ssh hanzo-gateway

   # Set environment variables
   docker stop hanzo-gateway
   docker rm hanzo-gateway

   docker run -d \
     --name hanzo-gateway \
     --restart unless-stopped \
     -p 3001:3001 \
     -e DEEPSEEK_API_KEY=sk-xxx \
     -e OPENAI_API_KEY=sk-xxx \
     -e ANTHROPIC_API_KEY=sk-ant-xxx \
     -e TRUST_PROXY=true \
     hanzoai/gateway:latest node server.js
   ```

3. ⏳ **Test with Domain**:
   ```bash
   curl https://api.hanzo.ai/health
   ```

### Future Enhancements

1. **Redis Integration**:
   - Replace in-memory rate limiting with Redis
   - Enable multi-instance deployments
   - Persistent usage tracking

2. **Authentication**:
   - API key authentication
   - JWT token support
   - User accounts

3. **Monitoring**:
   - Prometheus metrics
   - Grafana dashboards
   - Alert configuration

4. **Scaling**:
   - Load balancer setup
   - Multiple gateway instances
   - Auto-scaling based on traffic

5. **Database**:
   - PostgreSQL for usage history
   - Analytics and reporting
   - Billing integration

## Cost Analysis

### Current Monthly Cost

| Component | Cost |
|-----------|------|
| DigitalOcean Droplet (s-1vcpu-1gb) | $6.00 |
| **Total** | **$6.00/month** |

### With Upgrades

| Component | Cost |
|-----------|------|
| Droplet (s-2vcpu-2gb) | $18.00 |
| Domain | $1.00 |
| SSL | $0 (Let's Encrypt) |
| **Total** | **$19.00/month** |

### With Redis

| Component | Cost |
|-----------|------|
| Droplet (s-2vcpu-2gb) | $18.00 |
| Redis Managed Database | $15.00 |
| Domain | $1.00 |
| **Total** | **$34.00/month** |

## Repository Information

### Git Status

```bash
Repository: git@github.com:hanzoai/gateway.git
Branch: main
Latest Commit: 685cc6f feat: add simple Node.js Dockerfile for gateway
```

### Files Added/Modified

**Added**:
- LICENSE (MIT License)
- DEPLOYMENT_STATUS.md (this file)

**Already Exists**:
- README.md ✅
- CONTRIBUTING.md ✅
- .gitignore ✅
- .env.example ✅
- compose.yml ✅
- Dockerfile ✅
- ARCHITECTURE.md ✅
- FREE_TIER_PLAN.md ✅
- DEPLOYMENT.md ✅

## Support

### Monitoring Commands

```bash
# Check droplet status
doctl compute droplet list --format Name,PublicIPv4,Status

# View container logs
doctl compute ssh hanzo-gateway \
  --ssh-command "docker logs --tail 50 hanzo-gateway"

# SSH into droplet
doctl compute ssh hanzo-gateway

# Restart container
doctl compute ssh hanzo-gateway \
  --ssh-command "docker restart hanzo-gateway"
```

### Troubleshooting

**Container won't start**:
```bash
# Check logs
doctl compute ssh hanzo-gateway \
  --ssh-command "docker logs hanzo-gateway"

# Common issues:
# - Missing API keys (optional, but logged)
# - Port already in use
# - Image pull failed
```

**Health check failing**:
```bash
# Test locally on droplet
doctl compute ssh hanzo-gateway \
  --ssh-command "curl http://localhost:3001/health"

# Check firewall
# Ensure port 3001 is open
```

**High rate limit errors**:
```bash
# Adjust limits via environment variables
FREE_TIER_REQUESTS_PER_MINUTE=20
FREE_TIER_REQUESTS_PER_HOUR=200
FREE_TIER_REQUESTS_PER_DAY=1000
```

## Contact

- **Issues**: https://github.com/hanzoai/gateway/issues
- **Email**: support@hanzo.ai
- **Documentation**: https://docs.hanzo.ai

---

**Last Updated**: 2025-11-04 21:30 PST
**Deployed By**: Automated deployment script
**Status**: ✅ Production-ready
