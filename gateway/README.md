# Hanzo AI Inference Gateway

Secure, scalable inference API gateway for serving AI models through your DigitalOcean credits.

## 🎯 Services

- **inference.hanzo.ai** - LLM inference (chat completions)
- **embedding.hanzo.ai** - Embedding generation
- **admin.hanzo.ai** - Admin dashboard (device approval, usage stats)

## 🚀 Quick Start

```bash
# 1. Add your DigitalOcean API key
nano .env
# DIGITALOCEAN_API_KEY=dop_v1_YOUR_KEY_HERE

# 2. Start services
docker-compose up -d

# 3. Test
curl http://localhost:3001/health
curl http://localhost:3002/health
```

## 📚 Documentation

- **[SETUP.md](./SETUP.md)** - Complete setup guide
- **[.env.example](./.env.example)** - Environment variable reference

## 🔒 Security

- ✅ API keys never exposed to clients
- ✅ Device registration required
- ✅ Multi-layer rate limiting
- ✅ Cost controls & budget limits

## 📊 Features

- ✅ Support for 40+ models (open source + commercial)
- ✅ Free tier with 100 requests/day
- ✅ 7-day trial for new users
- ✅ Real-time cost tracking
- ✅ Usage analytics
- ✅ Automatic abuse prevention

## 💰 Economics

**Per User (Free Tier):**
- 100 requests/day
- 10,000 tokens/day
- Cost: ~$0.30/month

**Scale:**
- 100 users: $30/month
- 1,000 users: $300/month
- 10,000 users: $3,000/month

## 🛠️ Tech Stack

- Node.js (Hono framework)
- PostgreSQL (user data, logs)
- Redis (rate limiting)
- Nginx (reverse proxy)
- Docker & Docker Compose

## 📞 Support

- Email: tech@hanzo.ai
- Docs: See SETUP.md
