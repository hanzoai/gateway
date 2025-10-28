# Hanzo AI Gateway

> **Production-ready multi-provider AI inference platform for Hanzo ecosystem**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build and Push](https://github.com/hanzoai/gateway/workflows/Build%20and%20Push%20Docker%20Image/badge.svg)](https://github.com/hanzoai/gateway/actions)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://hub.docker.com/r/hanzoai/gateway)

Hanzo Gateway provides secure, cost-effective AI inference across multiple providers (DigitalOcean, OpenAI, Claude) with built-in rate limiting, cost controls, and device authentication.

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/hanzoai/gateway.git
cd gateway

# Configure API keys
cp gateway/.env.example gateway/.env
# Edit gateway/.env and add your API keys

# Start services
docker-compose up -d

# Test inference
curl http://localhost:3001/health
```

## 📦 What's Included

### 1. Cloud Node (`docker/`)
- **Rust-based Hanzo Node** (port 9550)
- Full hanzo-node capabilities
- Integrated with hanzo-desktop
- Multi-provider AI agent support
- Production-ready systemd service

### 2. Inference Gateway (`gateway/`)
- **Node.js API proxy** (ports 3001, 3002)
- Secure API key management
- Multi-layer rate limiting
- Cost tracking and controls
- Device authentication

## 🌟 Features

### Multi-Provider Support
- ✅ **DigitalOcean Gradient AI** (Default - Qwen3-32B)
  - 40+ models available
  - $0.30-$1.20 per 1M tokens
  - Serverless inference
  
- ✅ **OpenAI** (Premium)
  - GPT-4o, GPT-4o-mini, o1
  - Vision capabilities
  - Function calling

- ✅ **Anthropic Claude** (Reasoning)
  - Claude 3.5 Sonnet, Opus
  - 200K context window
  - Safety-focused

### Security & Rate Limiting
- 🔒 **Device Authentication** - JWT-based session management
- 🚦 **Multi-layer Rate Limiting**
  - Per device: 100 req/day (free tier)
  - Per IP: 500 req/day
  - Per user: 1000 req/day
  - Burst protection: 5 req/min
- 💰 **Cost Controls**
  - Daily budget limits
  - Real-time tracking
  - Auto-pause on overage

### Production Features
- 🐳 **Docker Compose** deployment
- 🔄 **Automatic failover** between providers
- 📊 **Usage analytics** and monitoring
- 🔐 **SSL/TLS** ready (Nginx reverse proxy)
- 📝 **Comprehensive logging**
- 🧪 **Full test suite** with CI/CD

## 📖 Documentation

### Quick Links
- [Cloud Node Setup](./docker/README.md) - Deploy Hanzo Node with AI providers
- [Multi-Provider Config](./docker/PROVIDERS_SETUP.md) - Configure DO, OpenAI, Claude
- [Gateway Setup](./gateway/SETUP.md) - API proxy and rate limiting
- [GitHub CI/CD](./gateway/GITHUB_SETUP.md) - Automated testing and deployment

### Architecture

```
┌─────────────────┐
│ hanzo-desktop   │
│   (client)      │
└────────┬────────┘
         │
         v
┌─────────────────┐     ┌──────────────────┐
│  Cloud Node     │────▶│  Gateway         │
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

## 🛠️ Installation

### Option 1: Docker (Recommended)

```bash
# 1. Clone repository
git clone https://github.com/hanzoai/inference.git
cd inference

# 2. Configure environment
cp gateway/.env.example gateway/.env
nano gateway/.env  # Add your API keys

# 3. Start all services
docker-compose up -d

# 4. Verify
curl http://localhost:9550/v2/health_check  # Cloud node
curl http://localhost:3001/health            # Inference gateway
```

### Option 2: Native (Development)

```bash
# Cloud Node (Rust)
cd docker
sudo cp env.conf /opt/hanzo-node/
sudo cp hanzo-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start hanzo-node

# Gateway (Node.js)
cd gateway
npm install
cp .env.example .env
nano .env  # Add your API keys
npm start
```

## ⚙️ Configuration

### 1. API Keys

Create `gateway/.env`:

```bash
# Required
DIGITALOCEAN_API_KEY=sk-do-YOUR_KEY_HERE
JWT_SECRET=<generate with: openssl rand -base64 32>

# Optional (for multi-provider support)
OPENAI_API_KEY=sk-proj-YOUR_KEY_HERE
ANTHROPIC_API_KEY=sk-ant-YOUR_KEY_HERE

# Service Configuration
NODE_ENV=production
INFERENCE_PORT=3001
EMBEDDING_PORT=3002
```

### 2. Cloud Node Configuration

Edit `docker/env.conf`:

```bash
# Default: Qwen3-32B on DigitalOcean
INITIAL_AGENT_NAMES=do_qwen32b,do_llama33_70b,openai_gpt4o,claude_sonnet
INITIAL_AGENT_URLS=https://inference.do-ai.run,https://inference.do-ai.run,https://api.openai.com,https://api.anthropic.com
INITIAL_AGENT_MODELS=openai:alibaba-qwen3-32b,openai:llama3.3-70b-instruct,openai:gpt-4o,anthropic:claude-3-5-sonnet-20241022
INITIAL_AGENT_API_KEYS=YOUR_DO_KEY,YOUR_DO_KEY,YOUR_OPENAI_KEY,YOUR_CLAUDE_KEY
```

### 3. Rate Limiting

Edit `gateway/.env`:

```bash
# Free tier limits
FREE_TIER_REQUESTS_PER_DAY=100
FREE_TIER_TOKENS_PER_DAY=10000

# Cost protection
DAILY_BUDGET_USD=50.00
MONTHLY_BUDGET_USD=1000.00
```

## 🧪 Testing

### Run Tests

```bash
# Gateway tests
cd gateway
npm test

# Expected output:
# ✅ All tests passed!
# 23/23 tests passing
```

### Manual Testing

```bash
# Test DigitalOcean inference
curl -X POST http://localhost:3001/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "alibaba-qwen3-32b",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# Test model listing
curl http://localhost:3001/v1/models

# Test health endpoint
curl http://localhost:3001/health
```

## 📊 Monitoring

### View Logs

```bash
# Cloud node logs
sudo journalctl -u hanzo-node -f

# Gateway logs
docker logs -f inference-gateway
```

### Usage Analytics

```bash
# Get usage stats
curl http://localhost:9550/v2/analytics/providers

# Response:
{
  "period": "last_30_days",
  "providers": {
    "digitalocean": {
      "requests": 45000,
      "tokens": 22500000,
      "cost_usd": 23.40
    }
  }
}
```

## 💰 Cost Estimation

Based on 1000 requests/day with 500 tokens average:

| Provider | Model | Monthly Cost |
|----------|-------|--------------|
| **DigitalOcean** | **Qwen3-32B** | **$23** ⭐ |
| DigitalOcean | Llama 3.3 70B | $34 |
| OpenAI | GPT-4o | $188 |
| Anthropic | Claude 3.5 | $270 |

**Recommendation**: Default to Qwen3-32B for 10x cost savings with excellent quality.

## 🚀 Deployment

### Production Deployment

1. **DigitalOcean Droplet**
   ```bash
   # Create droplet
   doctl compute droplet create hanzo-inference \
     --size s-2vcpu-4gb \
     --image debian-11-x64 \
     --region nyc1
   ```

2. **Domain Setup**
   ```bash
   # Point DNS to droplet IP
   inference.hanzo.ai → YOUR_DROPLET_IP
   embedding.hanzo.ai → YOUR_DROPLET_IP
   ```

3. **SSL/TLS**
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d inference.hanzo.ai -d embedding.hanzo.ai
   ```

4. **Start Services**
   ```bash
   cd /opt/hanzo-inference
   docker-compose up -d
   ```

### Environment-Specific Configs

**Development:**
```bash
INITIAL_AGENT_NAMES=do_qwen32b
INITIAL_AGENT_MODELS=openai:alibaba-qwen3-32b
```

**Staging:**
```bash
INITIAL_AGENT_NAMES=do_qwen32b,do_llama31_8b
INITIAL_AGENT_MODELS=openai:alibaba-qwen3-32b,openai:llama3.1-8b-instruct
```

**Production:**
```bash
INITIAL_AGENT_NAMES=do_qwen32b,do_llama33_70b,openai_gpt4o,claude_sonnet
INITIAL_AGENT_MODELS=openai:alibaba-qwen3-32b,openai:llama3.3-70b-instruct,openai:gpt-4o,anthropic:claude-3-5-sonnet-20241022
```

## 🔧 Troubleshooting

### Common Issues

**Tests Failing?**
```bash
# Check API key
curl https://inference.do-ai.run/v1/models \
  -H "Authorization: Bearer $DIGITALOCEAN_API_KEY"
```

**Rate Limit Errors?**
```bash
# Check current limits
curl http://localhost:3001/v1/rate_limit_status
```

**High Costs?**
```bash
# Review usage
curl http://localhost:9550/v2/analytics/providers

# Adjust limits
nano gateway/.env  # Lower DAILY_BUDGET_USD
docker-compose restart
```

## 📝 License

MIT License - see [LICENSE](./LICENSE) for details.

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) first.

## 🔗 Links

- **Website**: https://hanzo.ai
- **Documentation**: https://docs.hanzo.ai/gateway
- **Discord**: https://discord.gg/hanzo
- **GitHub**: https://github.com/hanzoai/gateway

## 📞 Support

- **Issues**: https://github.com/hanzoai/gateway/issues
- **Email**: support@hanzo.ai
- **Discord**: https://discord.gg/hanzo

---

**Built with ❤️ by the Hanzo AI team**
