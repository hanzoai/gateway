# Hanzo AI Inference Gateway - Setup Guide
## inference.hanzo.ai + embedding.hanzo.ai

**Quick Start:** 15 minutes to deployment!

---

## 📁 Project Structure

```
inference-gateway/
├── .env                          # ← YOUR API KEYS GO HERE
├── .env.example                  # Template
├── docker-compose.yml            # Multi-service deployment
├── nginx/
│   └── nginx.conf               # Reverse proxy config
├── inference/                   # Inference service
│   ├── Dockerfile
│   ├── package.json
│   └── src/
├── embedding/                   # Embedding service
│   ├── Dockerfile
│   ├── package.json
│   └── src/
├── shared/                      # Shared utilities
│   ├── init.sql                 # Database schema
│   └── lib/
└── admin/                       # Admin dashboard (optional)
```

---

## 🚀 Quick Setup

### Step 1: Add Your DigitalOcean API Key (2 mins)

```bash
cd ~/work/hanzo/inference-gateway

# Open .env file
nano .env

# Add your DigitalOcean API key:
# DIGITALOCEAN_API_KEY=dop_v1_YOUR_KEY_HERE
```

**Where to get the key:**
1. Go to: https://cloud.digitalocean.com/ai/serverless-inference
2. Click "Create model access key"
3. Copy the key (starts with `dop_v1_`)
4. Paste into `.env` file

### Step 2: Generate Secrets (1 min)

```bash
# Generate JWT secret
openssl rand -base64 32

# Add to .env:
# JWT_SECRET=<paste the output here>
```

### Step 3: Deploy Locally (5 mins)

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f inference
docker-compose logs -f embedding
```

### Step 4: Test It! (2 mins)

```bash
# Test inference service
curl http://localhost:3001/health
# Should return: {"status":"healthy","service":"inference"}

# Test embedding service
curl http://localhost:3002/health
# Should return: {"status":"healthy","service":"embedding"}

# Test inference (requires device registration first)
curl -X POST http://localhost:3001/v1/devices/register \
  -H "Content-Type: application/json" \
  -d '{
    "deviceName": "Test Device",
    "platform": "macos",
    "version": "1.0.0"
  }'
```

---

## 🌐 Production Deployment

### Step 1: Create Droplet (5 mins)

```bash
# DigitalOcean Droplet specs:
# - Ubuntu 24.04 LTS
# - 2GB RAM / 1 CPU ($12/month)
# - 50GB SSD
# - Location: Nearest to users

# SSH into droplet
ssh root@YOUR_DROPLET_IP
```

### Step 2: Install Dependencies (5 mins)

```bash
# Update system
apt update && apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh

# Install Docker Compose
apt install docker-compose-plugin -y

# Install Nginx & Certbot
apt install nginx certbot python3-certbot-nginx -y
```

### Step 3: Deploy Code (5 mins)

```bash
# Clone or copy your code
git clone https://github.com/your-org/hanzo-inference-gateway
cd hanzo-inference-gateway

# Copy .env file
nano .env
# Paste your DigitalOcean API key

# Start services
docker compose up -d
```

### Step 4: Configure DNS (2 mins)

```
Point these domains to your Droplet IP:

inference.hanzo.ai  → YOUR_DROPLET_IP
embedding.hanzo.ai  → YOUR_DROPLET_IP
admin.hanzo.ai      → YOUR_DROPLET_IP
```

### Step 5: Get SSL Certificates (5 mins)

```bash
# Stop nginx
systemctl stop nginx

# Get certificates
certbot certonly --standalone \
  -d inference.hanzo.ai \
  -d embedding.hanzo.ai \
  -d admin.hanzo.ai \
  --agree-tos \
  -m your@email.com

# Start nginx
docker compose up -d nginx
```

### Step 6: Verify (2 mins)

```bash
# Test inference service
curl https://inference.hanzo.ai/health

# Test embedding service
curl https://embedding.hanzo.ai/health

# Check logs
docker compose logs -f
```

---

## 🔧 Configuration

### Environment Variables

**Required:**
- `DIGITALOCEAN_API_KEY` - Your DO Gradient AI API key

**Recommended:**
- `JWT_SECRET` - For session tokens (generate with openssl)
- `DAILY_BUDGET_USD` - Cost limit (default: $50)
- `FREE_TIER_REQUESTS_PER_DAY` - Rate limit (default: 100)

**Optional:**
- `ANTHROPIC_API_KEY` - For Claude models
- `OPENAI_API_KEY` - For GPT models
- `SLACK_WEBHOOK_URL` - For alerts

### Rate Limits

**Free Tier (Default):**
```env
FREE_TIER_REQUESTS_PER_DAY=100
FREE_TIER_TOKENS_PER_DAY=10000
FREE_TIER_REQUESTS_PER_MINUTE=5
FREE_TIER_MODELS=llama3-8b-instruct,mistral-nemo-instruct-2407
```

**Paid Tier:**
```env
PAID_TIER_REQUESTS_PER_DAY=10000
PAID_TIER_TOKENS_PER_DAY=1000000
PAID_TIER_REQUESTS_PER_MINUTE=100
```

### Supported Models

**Open Source (Free with DO credits):**
- `llama3.3-70b-instruct` - Meta Llama 3.3 70B
- `llama3-8b-instruct` - Meta Llama 3.1 8B
- `deepseek-r1-distill-llama-70b` - DeepSeek R1
- `alibaba-qwen3-32b` - Alibaba Qwen3 32B
- `mistral-nemo-instruct-2407` - Mistral NeMo 12B
- `openai-gpt-oss-120b` - GPT OSS 120B
- `openai-gpt-oss-20b` - GPT OSS 20B

**Commercial (Require partner API keys):**
- Anthropic: Claude 4, Claude 3.7, Claude 3.5
- OpenAI: GPT-5, GPT-4.1, GPT-4o, o1, o3

**Embeddings:**
- `Alibaba-NLP/gte-large-en-v1.5`
- `sentence-transformers/all-MiniLM-L6-v2`
- `sentence-transformers/multi-qa-mpnet-base-dot-v1`

---

## 📊 Service Endpoints

### Inference Service (inference.hanzo.ai)

**Chat Completions:**
```bash
POST https://inference.hanzo.ai/v1/chat/completions
Content-Type: application/json
X-Device-ID: your-device-id
X-Session-Token: your-session-token

{
  "model": "llama3-8b-instruct",
  "messages": [
    {"role": "user", "content": "Hello!"}
  ],
  "max_tokens": 100,
  "temperature": 0.7
}
```

**Device Registration:**
```bash
POST https://inference.hanzo.ai/v1/devices/register
Content-Type: application/json

{
  "deviceName": "My Device",
  "platform": "macos",
  "version": "1.0.0"
}
```

**Usage Stats:**
```bash
GET https://inference.hanzo.ai/v1/usage/stats
X-Device-ID: your-device-id
X-Session-Token: your-session-token
```

### Embedding Service (embedding.hanzo.ai)

**Generate Embeddings:**
```bash
POST https://embedding.hanzo.ai/v1/embeddings
Content-Type: application/json
X-Device-ID: your-device-id
X-Session-Token: your-session-token

{
  "model": "sentence-transformers/all-MiniLM-L6-v2",
  "input": ["Text to embed", "Another text"]
}
```

---

## 🔒 Security

### API Key Protection
- ✅ Stored in `.env` (never in code)
- ✅ Docker secrets for production
- ✅ AWS Secrets Manager (optional)
- ✅ Never exposed to clients

### Device Authentication
- ✅ Device registration required
- ✅ Manual admin approval
- ✅ Session tokens (JWT)
- ✅ Revocable access

### Rate Limiting
- ✅ Per device limits
- ✅ Per IP limits
- ✅ Per user limits
- ✅ Global cost limits

---

## 📈 Monitoring

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f inference
docker compose logs -f embedding

# Tail last 100 lines
docker compose logs --tail=100 inference
```

### Check Metrics

```bash
# Database size
docker compose exec db psql -U hanzo_user -d hanzo_gateway -c "
  SELECT pg_size_pretty(pg_database_size('hanzo_gateway'));"

# Redis keys
docker compose exec redis redis-cli DBSIZE

# Service health
curl https://inference.hanzo.ai/health
curl https://embedding.hanzo.ai/health
```

### Cost Tracking

```bash
# Today's cost
curl https://inference.hanzo.ai/admin/costs/today \
  -H "Authorization: Bearer ADMIN_TOKEN"

# Monthly report
curl https://inference.hanzo.ai/admin/costs/monthly?month=2025-10 \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

---

## 🐛 Troubleshooting

### "Cannot connect to database"
```bash
# Check database is running
docker compose ps db

# View database logs
docker compose logs db

# Restart database
docker compose restart db
```

### "Redis connection refused"
```bash
# Check Redis
docker compose ps redis
docker compose logs redis

# Test Redis
docker compose exec redis redis-cli ping
```

### "DIGITALOCEAN_API_KEY not set"
```bash
# Check .env file exists
ls -la .env

# Verify key is set
grep DIGITALOCEAN_API_KEY .env

# Restart services to reload
docker compose restart
```

### "SSL certificate error"
```bash
# Renew certificates
certbot renew

# Reload nginx
docker compose restart nginx
```

---

## 🔄 Updates

### Update Services

```bash
# Pull latest code
git pull

# Rebuild and restart
docker compose down
docker compose build
docker compose up -d

# Check logs
docker compose logs -f
```

### Update SSL Certificates

```bash
# Certbot auto-renewal (runs twice daily)
systemctl status certbot.timer

# Manual renewal
certbot renew
docker compose restart nginx
```

---

## 💰 Cost Estimation

### Monthly Costs

**Infrastructure:**
- DigitalOcean Droplet: $12/month (2GB)
- Domain + SSL: Free (Let's Encrypt)

**DigitalOcean API Usage:**
- 100 free users @ $0.30/user = $30/month
- 1,000 free users @ $0.30/user = $300/month
- 10,000 free users @ $0.30/user = $3,000/month

**Total for 1,000 free users:**
- Infrastructure: $12
- API usage: $300
- **Total: $312/month**

With 50 paid users @ $9/month = $450 revenue  
**Net profit: ~$138/month**

---

## 📞 Support

- **Documentation:** /Users/z/work/hanzo/inference-gateway/
- **Issues:** https://github.com/your-org/hanzo-inference-gateway/issues
- **Email:** tech@hanzo.ai

---

## ✅ Checklist

### Pre-Deployment
- [ ] DigitalOcean API key obtained
- [ ] .env file configured
- [ ] JWT secret generated
- [ ] Tested locally with docker-compose

### Production Deployment
- [ ] Droplet created
- [ ] Docker installed
- [ ] Code deployed
- [ ] DNS configured
- [ ] SSL certificates installed
- [ ] Services running
- [ ] Health checks passing

### Post-Deployment
- [ ] Monitoring set up
- [ ] Alerts configured
- [ ] Cost tracking enabled
- [ ] Admin dashboard accessible
- [ ] First test user registered

---

**Status:** 🚀 Ready to deploy!

Just add your DigitalOcean API key to `.env` and run `docker compose up -d`!
