# Multi-Provider AI Configuration Guide

This guide explains how to configure Hanzo Cloud Node with multiple AI providers (DigitalOcean, OpenAI, Claude).

## Overview

Hanzo Cloud Node supports multiple AI providers simultaneously:

- **DigitalOcean Gradient AI Platform** (Default)
  - Primary: Qwen3-32B (best balance)
  - Alternative: Llama 3.3 70B, Llama 3.1 8B
  - Cost-effective serverless inference
  
- **OpenAI**
  - GPT-4o for premium tasks
  - Fallback for commercial models
  
- **Anthropic Claude**
  - Claude 3.5 Sonnet for reasoning
  - Alternative for complex queries

## Configuration Files

### 1. Environment Configuration (`env.conf`)

```bash
# Default AI Provider: DigitalOcean Gradient AI Platform
# Primary model: Qwen3-32B (best balance of quality/speed/cost)
# Users can configure additional providers via desktop app
INITIAL_AGENT_NAMES=do_qwen32b,do_llama33_70b,do_llama31_8b,openai_gpt4o,claude_sonnet
INITIAL_AGENT_URLS=https://inference.do-ai.run,https://inference.do-ai.run,https://inference.do-ai.run,https://api.openai.com,https://api.anthropic.com
INITIAL_AGENT_MODELS=openai:alibaba-qwen3-32b,openai:llama3.3-70b-instruct,openai:llama3.1-8b-instruct,openai:gpt-4o,anthropic:claude-3-5-sonnet-20241022
INITIAL_AGENT_API_KEYS=YOUR_DO_KEY,YOUR_DO_KEY,YOUR_DO_KEY,YOUR_OPENAI_KEY,YOUR_CLAUDE_KEY
```

### 2. API Keys Setup

Create a `.env.secret` file (never commit this):

```bash
# DigitalOcean Gradient AI Platform
DIGITALOCEAN_API_KEY=sk-do-YOUR_DIGITALOCEAN_API_KEY_HERE

# OpenAI
OPENAI_API_KEY=sk-proj-...your-key-here...

# Anthropic Claude
ANTHROPIC_API_KEY=sk-ant-...your-key-here...
```

Then update `env.conf`:

```bash
INITIAL_AGENT_API_KEYS=$DIGITALOCEAN_API_KEY,$DIGITALOCEAN_API_KEY,$DIGITALOCEAN_API_KEY,$OPENAI_API_KEY,$ANTHROPIC_API_KEY
```

## Provider Details

### DigitalOcean Gradient AI Platform

**Why Default:**
- ✅ Cost-effective ($0.30-$1.20 per 1M tokens)
- ✅ 40+ models available
- ✅ Serverless (no infra management)
- ✅ Good latency
- ✅ Qwen3-32B excellent quality

**Available Models:**
```
alibaba-qwen3-32b              # Primary (32B params, multilingual)
llama3.3-70b-instruct         # Alternative (70B params, high quality)
llama3.1-8b-instruct          # Fast (8B params, low latency)
mistral-nemo-instruct-2407    # Specialized
deepseek-r1                   # Reasoning
```

**API Format:**
```bash
curl https://inference.do-ai.run/v1/chat/completions \
  -H "Authorization: Bearer $DIGITALOCEAN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "alibaba-qwen3-32b",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

### OpenAI

**When to Use:**
- Premium quality needed
- Specific GPT-4o features
- Commercial use cases

**Available Models:**
```
gpt-4o              # Latest flagship
gpt-4o-mini         # Fast and cheap
o1                  # Advanced reasoning
```

**API Format:**
```bash
curl https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

### Anthropic Claude

**When to Use:**
- Complex reasoning tasks
- Long context (200K tokens)
- Safety-critical applications

**Available Models:**
```
claude-3-5-sonnet-20241022    # Latest Sonnet
claude-3-7-sonnet             # Production
claude-3-opus                 # Maximum capability
claude-3.5-haiku              # Fast
```

**API Format:**
```bash
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

## Cost Comparison

### Per 1M Tokens (Input/Output):

| Provider | Model | Input | Output | Notes |
|----------|-------|-------|--------|-------|
| **DigitalOcean** | Qwen3-32B | $0.30 | $1.20 | **Default** |
| DigitalOcean | Llama 3.3 70B | $0.60 | $0.90 | High quality |
| DigitalOcean | Llama 3.1 8B | $0.20 | $0.20 | Fast |
| OpenAI | GPT-4o | $2.50 | $10.00 | Premium |
| OpenAI | GPT-4o-mini | $0.15 | $0.60 | Cheap |
| Anthropic | Claude 3.5 Sonnet | $3.00 | $15.00 | Reasoning |
| Anthropic | Claude 3.5 Haiku | $0.25 | $1.25 | Fast |

### Monthly Cost Estimates (1000 requests/day, 500 tokens avg):

| Provider | Model | Monthly Cost |
|----------|-------|--------------|
| **DigitalOcean** | **Qwen3-32B** | **$23** |
| DigitalOcean | Llama 3.3 70B | $34 |
| DigitalOcean | Llama 3.1 8B | $6 |
| OpenAI | GPT-4o | $188 |
| OpenAI | GPT-4o-mini | $11 |
| Anthropic | Claude Sonnet | $270 |

## Quick Start

### 1. Get API Keys

**DigitalOcean:**
1. Go to https://cloud.digitalocean.com/
2. Navigate to API → Tokens
3. Generate new token with "Read & Write" scope
4. Save token (starts with `sk-do-`)

**OpenAI:**
1. Go to https://platform.openai.com/api-keys
2. Create new secret key
3. Save key (starts with `sk-proj-` or `sk-`)

**Anthropic:**
1. Go to https://console.anthropic.com/settings/keys
2. Create new API key
3. Save key (starts with `sk-ant-`)

### 2. Configure Cloud Node

```bash
# Edit env.conf
sudo nano /opt/hanzo-node/env.conf

# Add your keys (comma-separated, matching order of INITIAL_AGENT_NAMES)
INITIAL_AGENT_API_KEYS=sk-do-YOUR_DO_KEY,sk-do-YOUR_DO_KEY,sk-do-YOUR_DO_KEY,sk-proj-YOUR_OPENAI_KEY,sk-ant-YOUR_CLAUDE_KEY
```

### 3. Restart Service

```bash
sudo systemctl restart hanzo-node
sudo systemctl status hanzo-node
```

### 4. Verify Configuration

```bash
# Check logs for successful initialization
sudo journalctl -u hanzo-node -f | grep "agent"

# Should see:
# ✅ Initialized agent: do_qwen32b
# ✅ Initialized agent: do_llama33_70b
# ✅ Initialized agent: do_llama31_8b
# ✅ Initialized agent: openai_gpt4o
# ✅ Initialized agent: claude_sonnet
```

## Testing Providers

### Test DigitalOcean Connection:

```bash
curl -X POST http://localhost:9550/v2/test_agent \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "do_qwen32b",
    "message": "Hello, test DigitalOcean"
  }'
```

### Test OpenAI Connection:

```bash
curl -X POST http://localhost:9550/v2/test_agent \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "openai_gpt4o",
    "message": "Hello, test OpenAI"
  }'
```

### Test Claude Connection:

```bash
curl -X POST http://localhost:9550/v2/test_agent \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "claude_sonnet",
    "message": "Hello, test Claude"
  }'
```

## Provider Selection Strategy

### Default (Qwen3-32B on DigitalOcean)
- ✅ General chat and assistance
- ✅ Code generation
- ✅ Document analysis
- ✅ Multilingual tasks
- ✅ Cost-effective at scale

### When to Use Llama 3.3 70B (DigitalOcean)
- Complex reasoning tasks
- Need higher quality than Qwen3-32B
- Still want cost efficiency
- Technical documentation

### When to Use GPT-4o (OpenAI)
- Maximum quality needed
- Commercial applications
- Vision tasks (GPT-4o with vision)
- Function calling requirements

### When to Use Claude Sonnet (Anthropic)
- Long context needed (200K tokens)
- Complex reasoning and analysis
- Safety-critical applications
- Ethical considerations important

## Automatic Failover

Hanzo Node supports automatic failover:

1. **Primary**: Qwen3-32B (DigitalOcean)
2. **Fallback 1**: Llama 3.3 70B (DigitalOcean)
3. **Fallback 2**: GPT-4o-mini (OpenAI)

Configure in `env.conf`:
```bash
ENABLE_AUTO_FAILOVER=true
FAILOVER_MAX_RETRIES=3
FAILOVER_TIMEOUT_MS=5000
```

## Rate Limits

### DigitalOcean Gradient AI Platform:
- **Default**: No strict limits
- **Recommended**: 100 req/sec per model
- **Cost-based**: Monitor via DO dashboard

### OpenAI:
- **Free Tier**: 3 RPM, 200 RPD
- **Tier 1**: 500 RPM, 10K RPD
- **Tier 5**: 10K RPM, 5M TPD

### Anthropic:
- **Free Tier**: 5 RPM
- **Build Tier 1**: 50 RPM
- **Scale**: 1K+ RPM

## Environment-Specific Configs

### Development:
```bash
INITIAL_AGENT_NAMES=do_qwen32b
INITIAL_AGENT_URLS=https://inference.do-ai.run
INITIAL_AGENT_MODELS=openai:alibaba-qwen3-32b
INITIAL_AGENT_API_KEYS=$DIGITALOCEAN_API_KEY
```

### Staging:
```bash
INITIAL_AGENT_NAMES=do_qwen32b,do_llama31_8b
INITIAL_AGENT_URLS=https://inference.do-ai.run,https://inference.do-ai.run
INITIAL_AGENT_MODELS=openai:alibaba-qwen3-32b,openai:llama3.1-8b-instruct
INITIAL_AGENT_API_KEYS=$DIGITALOCEAN_API_KEY,$DIGITALOCEAN_API_KEY
```

### Production:
```bash
INITIAL_AGENT_NAMES=do_qwen32b,do_llama33_70b,openai_gpt4o,claude_sonnet
INITIAL_AGENT_URLS=https://inference.do-ai.run,https://inference.do-ai.run,https://api.openai.com,https://api.anthropic.com
INITIAL_AGENT_MODELS=openai:alibaba-qwen3-32b,openai:llama3.3-70b-instruct,openai:gpt-4o,anthropic:claude-3-5-sonnet-20241022
INITIAL_AGENT_API_KEYS=$DIGITALOCEAN_API_KEY,$DIGITALOCEAN_API_KEY,$OPENAI_API_KEY,$ANTHROPIC_API_KEY
```

## Security Best Practices

1. **Never commit API keys**
   ```bash
   # Add to .gitignore
   echo "*.secret" >> .gitignore
   echo ".env.*" >> .gitignore
   ```

2. **Use environment variables**
   ```bash
   # Load from secure storage
   source /opt/hanzo-node/.env.secret
   ```

3. **Rotate keys regularly**
   - DigitalOcean: Every 90 days
   - OpenAI: Every 90 days
   - Anthropic: Every 90 days

4. **Monitor usage**
   ```bash
   # Set up alerts for unusual activity
   USAGE_ALERT_THRESHOLD_USD=100
   USAGE_ALERT_EMAIL=admin@hanzo.ai
   ```

5. **Restrict key permissions**
   - Only grant necessary scopes
   - Use separate keys for dev/staging/prod
   - Enable IP restrictions when available

## Monitoring and Analytics

### Track Provider Usage:

```bash
# View usage stats
curl http://localhost:9550/v2/analytics/providers

# Response:
{
  "period": "last_30_days",
  "providers": {
    "digitalocean": {
      "requests": 45000,
      "tokens": 22500000,
      "cost_usd": 23.40,
      "avg_latency_ms": 350
    },
    "openai": {
      "requests": 5000,
      "tokens": 2500000,
      "cost_usd": 18.75,
      "avg_latency_ms": 420
    },
    "anthropic": {
      "requests": 1000,
      "tokens": 500000,
      "cost_usd": 9.00,
      "avg_latency_ms": 380
    }
  }
}
```

### Set Cost Alerts:

```bash
# In env.conf
COST_ALERT_DAILY_USD=10
COST_ALERT_MONTHLY_USD=200
ALERT_EMAIL=admin@hanzo.ai
```

## Troubleshooting

### Provider Not Working:

1. **Check API key validity**
   ```bash
   # DigitalOcean
   curl https://inference.do-ai.run/v1/models \
     -H "Authorization: Bearer $DIGITALOCEAN_API_KEY"
   
   # OpenAI
   curl https://api.openai.com/v1/models \
     -H "Authorization: Bearer $OPENAI_API_KEY"
   
   # Anthropic
   curl https://api.anthropic.com/v1/messages \
     -H "x-api-key: $ANTHROPIC_API_KEY" \
     -H "anthropic-version: 2023-06-01" \
     -d '{"model":"claude-3-5-sonnet-20241022","max_tokens":10,"messages":[{"role":"user","content":"test"}]}'
   ```

2. **Check rate limits**
   - View provider dashboard
   - Check current quota usage
   - Upgrade tier if needed

3. **Check logs**
   ```bash
   sudo journalctl -u hanzo-node -f | grep "provider\|agent\|error"
   ```

4. **Test connectivity**
   ```bash
   # Test DNS resolution
   nslookup inference.do-ai.run
   nslookup api.openai.com
   nslookup api.anthropic.com
   
   # Test HTTPS connection
   curl -I https://inference.do-ai.run
   ```

### Common Errors:

**401 Unauthorized**
- Invalid or expired API key
- Check key format matches provider
- Regenerate key if necessary

**429 Too Many Requests**
- Rate limit exceeded
- Upgrade tier or reduce request rate
- Implement exponential backoff

**503 Service Unavailable**
- Provider having issues
- Check status page
- Failover to alternative provider

## Support

- **DigitalOcean**: https://status.digitalocean.com/
- **OpenAI**: https://status.openai.com/
- **Anthropic**: https://status.anthropic.com/
- **Hanzo**: support@hanzo.ai

## Next Steps

1. ✅ Configure API keys in env.conf
2. ✅ Test each provider connection
3. ✅ Monitor usage and costs
4. ✅ Configure hanzo-desktop to use docker
5. ✅ Set up alerts and monitoring
6. ✅ Plan provider strategy based on usage
