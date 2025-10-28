# Hanzo AI - Simplified Architecture

## Overview
Clean separation of concerns with gateway as a simple proxy and hanzo-id as the service layer for rate limiting, auth, and usage tracking.

## Service Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Requests                         │
│          (Desktop App, Web, CLI, Direct API)                 │
└────────────────────────────┬────────────────────────────────┘
                             │
                             v
                  ┌──────────────────────┐
                  │     hanzo-id         │ ← Auth + Rate Limiting
                  │   (Service Layer)    │ ← Usage Tracking
                  │    Casdoor-based     │ ← API Key Management
                  └──────────┬───────────┘
                             │
                             v
                  ┌──────────────────────┐
                  │   hanzo-gateway      │ ← Simple Proxy
                  │  (did:hanzo:gateway) │ ← No auth/rate limiting
                  │      Port 9550       │ ← Just routes requests
                  └──────────┬───────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         v                   v                   v
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   OpenAI API    │ │  Anthropic API  │ │  Local Nodes    │
│   (GPT-4, etc)  │ │  (Claude, etc)  │ │ (User-hosted)   │
└─────────────────┘ └─────────────────┘ └─────────────────┘
         │                   │                   │
         └───────────────────┴───────────────────┘
                             │
                             v
                  ┌──────────────────────┐
                  │    hanzo-cloud       │ ← Analytics
                  │   (casibase-based)   │ ← Billing
                  │    Usage Tracking    │ ← Dashboards
                  └──────────────────────┘
```

## Component Responsibilities

### 1. hanzo-id (Service Layer)
**Repository**: `~/work/hanzo/id`
**Technology**: Go (Casdoor fork)
**Port**: 8000

**Responsibilities**:
- ✅ Authentication (SSO, API keys)
- ✅ Authorization (Casbin policies)
- ✅ Rate limiting (per IP, per user)
- ✅ Usage tracking
- ✅ API key management
- ✅ User management
- ✅ Billing integration

**Why Casdoor?**
- Battle-tested auth platform
- Built-in SSO (OAuth, SAML, LDAP)
- API key management
- User/org/role management
- Already supports usage tracking

### 2. hanzo-gateway (Proxy Layer)
**Repository**: `~/work/hanzo/gateway`
**Technology**: Rust (hanzo-node)
**Port**: 9550
**Identity**: `did:hanzo:gateway`

**Responsibilities**:
- ✅ Route requests to providers
- ✅ Load balancing
- ✅ Failover
- ✅ Request/response transformation
- ❌ NO auth/rate limiting (handled by hanzo-id)
- ❌ NO usage tracking (sent to hanzo-cloud)

**Why Keep It Simple?**
- Faster deployment
- Easier scaling (stateless)
- Single responsibility
- Works with or without auth layer

### 3. hanzo-cloud (Analytics & Billing)
**Repository**: `~/work/hanzo/cloud`
**Technology**: Go (Casibase fork)
**Port**: TBD

**Responsibilities**:
- ✅ Usage analytics
- ✅ Cost tracking
- ✅ Billing integration
- ✅ Dashboards
- ✅ Reports
- ✅ MCP (Model Context Protocol)
- ✅ Vector search / RAG

**Why Casibase?**
- AI-native knowledge base
- Built-in MCP support
- Vector search (pgvector)
- Analytics dashboards
- Chat/agent capabilities

### 4. hanzo-console (UI)
**Repository**: `~/work/hanzo/console`
**Technology**: React/Next.js
**Port**: 3000

**Responsibilities**:
- ✅ User dashboard
- ✅ Usage visualizations
- ✅ API key management
- ✅ Billing portal
- ✅ Settings

## Request Flow

### Free Tier (Anonymous)
```
1. User → hanzo-id (check IP rate limit)
   ├─ Allowed? → Continue
   └─ Denied? → Return 429 Rate Limit

2. hanzo-id → hanzo-gateway (add request ID)

3. hanzo-gateway → Provider (OpenAI, etc)

4. Provider → hanzo-gateway → hanzo-id → User

5. hanzo-id → hanzo-cloud (log usage)
```

### Paid Tier (API Key)
```
1. User → hanzo-id (verify API key, check user limits)
   ├─ Valid? → Continue
   └─ Invalid? → Return 401 Unauthorized

2. hanzo-id → hanzo-gateway (add user ID, plan info)

3. hanzo-gateway → Provider (or local node)

4. Provider → hanzo-gateway → hanzo-id → User

5. hanzo-id → hanzo-cloud (log usage with user ID)
```

### Node Operator (LocalXpose-like)
```
1. User → hanzo-id (verify API key)
2. hanzo-id → hanzo-gateway (route to node ID)
3. hanzo-gateway → User's Local Node (via ngrok-like tunnel)
4. Local Node → hanzo-gateway → hanzo-id → User
5. hanzo-id → hanzo-cloud (track node usage)
```

## Configuration

### hanzo-id Configuration
```bash
# Upstream identity service
CASDOOR_URL=https://id.hanzo.ai

# Rate limits (per IP)
FREE_TIER_REQUESTS_PER_MINUTE=10
FREE_TIER_REQUESTS_PER_HOUR=100
FREE_TIER_REQUESTS_PER_DAY=500
FREE_TIER_TOKENS_PER_DAY=50000

# Paid tier limits (per user)
PAID_TIER_REQUESTS_PER_DAY=10000
PAID_TIER_TOKENS_PER_DAY=1000000

# Analytics endpoint
ANALYTICS_URL=https://cloud.hanzo.ai/api/track

# Gateway endpoint
GATEWAY_URL=https://gateway.hanzo.ai
```

### hanzo-gateway Configuration
```bash
# Identity
GLOBAL_IDENTITY_NAME=did:hanzo:gateway

# No auth/rate limiting config needed!
# Just provider endpoints:
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-...
TOGETHER_API_KEY=...
```

### hanzo-cloud Configuration
```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/hanzo_cloud
REDIS_URL=redis://localhost:6379

# Vector search
ENABLE_VECTOR_SEARCH=true
EMBEDDING_MODEL=text-embedding-3-small

# MCP
MCP_TOOLS_DIR=/opt/hanzo/mcp-tools
```

## Deployment Scenarios

### Development
```bash
# Start hanzo-id (auth layer)
cd ~/work/hanzo/id && make dev

# Start hanzo-gateway (proxy)
cd ~/work/hanzo/gateway && docker-compose up -d

# Start hanzo-cloud (analytics)
cd ~/work/hanzo/cloud && make dev

# Start hanzo-console (UI)
cd ~/work/hanzo/console && npm run dev
```

### Production (Free Plan Only)
```bash
# Option 1: Gateway only (no auth)
cd ~/work/hanzo/gateway
make deploy-full  # $6/month
```

### Production (Full Stack)
```bash
# DigitalOcean Kubernetes
# 1. hanzo-id: 2 pods (load balanced)
# 2. hanzo-gateway: 3 pods (auto-scaling)
# 3. hanzo-cloud: 2 pods
# 4. hanzo-console: static (Vercel/Cloudflare)
# 5. PostgreSQL: Managed database
# 6. Redis: Managed cache

# Cost: ~$100-200/month for 1000+ users
```

## Benefits of This Architecture

### 1. Separation of Concerns
- Gateway = routing only
- hanzo-id = auth/rate limiting
- hanzo-cloud = analytics/billing
- Each service can be scaled independently

### 2. Gradual Adoption
- Start with gateway only (free plan)
- Add hanzo-id when you need auth
- Add hanzo-cloud when you need analytics
- Add hanzo-console when you need UI

### 3. Standards-Based
- Casdoor = proven auth platform
- Casibase = AI-native analytics
- OpenAI API = standard interface
- MCP = standard tool protocol

### 4. Cost Effective
- Gateway: $6/month (basic droplet)
- With hanzo-id: $12/month (+ auth droplet)
- With full stack: $100-200/month (K8s + managed DBs)

### 5. Developer Friendly
- Simple gateway = easy to understand
- Standard APIs = easy to integrate
- Open source = easy to customize

## Migration Path

### Current State
```
✅ hanzo-gateway exists (simple proxy)
❌ hanzo-id not configured for gateway yet
❌ hanzo-cloud not set up
❌ hanzo-console needs updates
```

### Phase 1: Gateway Only (Now)
```bash
# Deploy gateway without auth
cd ~/work/hanzo/gateway
make deploy-full

# Test: curl http://gateway.hanzo.ai/health
# Free tier = unlimited for now
```

### Phase 2: Add Auth Layer (Week 2)
```bash
# Configure hanzo-id to wrap gateway
cd ~/work/hanzo/id
# Add gateway proxy config
# Deploy hanzo-id

# Update DNS:
# api.hanzo.ai → hanzo-id (with rate limiting)
# gateway.hanzo.ai → hanzo-gateway (direct access)
```

### Phase 3: Add Analytics (Week 3)
```bash
# Configure hanzo-cloud
cd ~/work/hanzo/cloud
# Set up usage tracking
# Connect to hanzo-id

# Deploy hanzo-console
cd ~/work/hanzo/console
# Update to show analytics
```

## API Endpoints

### Public (Through hanzo-id)
```
https://api.hanzo.ai/v1/chat/completions    # Auth + rate limited
https://api.hanzo.ai/v1/embeddings          # Auth + rate limited
https://api.hanzo.ai/v1/models              # Public
```

### Direct Gateway (No Auth - Development Only)
```
https://gateway.hanzo.ai/v1/chat/completions  # Direct, no rate limit
https://gateway.hanzo.ai/health               # Health check
```

### Console
```
https://console.hanzo.ai          # User dashboard
https://console.hanzo.ai/api-keys # API key management
https://console.hanzo.ai/usage    # Usage analytics
```

### Node Operators
```
https://api.hanzo.ai/v1/nodes/register        # Register node endpoint
https://USER_ID.node.hanzo.ai/v1/*           # User's node endpoint
```

## Security Considerations

### hanzo-id Security
- JWT token signing
- API key hashing (bcrypt)
- Rate limit storage (Redis)
- IP reputation checking
- Bot detection

### hanzo-gateway Security
- No sensitive data storage
- Stateless proxy
- Request validation
- Provider key rotation

### hanzo-cloud Security
- Encrypted data at rest
- Anonymized analytics (optional)
- GDPR compliance
- Data retention policies

## Monitoring

### Metrics to Track
- **hanzo-id**: Auth requests, rate limit violations, API key usage
- **hanzo-gateway**: Request latency, provider availability, error rates
- **hanzo-cloud**: Storage usage, query performance, costs

### Alerting
- hanzo-id down → Cannot auth
- hanzo-gateway down → Cannot serve requests
- hanzo-cloud down → No analytics (non-critical)

## Go SDK Architecture

### Current Go Projects

#### 1. go-sdk (API Client)
**Path**: `~/work/hanzo/go-sdk`
**Type**: Stainless-generated API client
**Purpose**: Client library for Hanzo AI APIs

Similar to python-sdk and js-sdk:
```go
import "github.com/hanzoai/go-sdk"

client := hanzoai.NewClient(
    option.WithAPIKey("sk-..."),
)
```

#### 2. dbx (Database Layer)
**Path**: `~/work/hanzo/dbx`
**Type**: Database abstraction
**Purpose**: Shared database utilities

Fork of go-ozzo/ozzo-dbx with improved SQLite support:
```go
import "github.com/hanzoai/dbx"

db, _ := dbx.Open("mysql", "user:pass@/db")
```

#### 3. id (Identity Service)
**Path**: `~/work/hanzo/id`
**Type**: Authentication service
**Purpose**: Casdoor-based auth platform

Not a library - standalone service that gateway uses.

#### 4. nexus (AI Platform)
**Path**: `~/work/hanzo/nexus`
**Type**: Casibase-based platform
**Purpose**: AI knowledge base + analytics

Not a library - standalone service (similar to hanzo-cloud).

### Go SDK Strategy

**Unlike rust-sdk** (which is a collection of shared crates), the Go ecosystem is organized as:

1. **go-sdk** = API client (like python-sdk/js-sdk)
2. **dbx** = Shared database utilities
3. **id**, **nexus**, etc. = Standalone services (not libraries)

**No consolidation needed** - Go projects are already well-organized:
- Reusable code → dbx, go-sdk
- Services → id, nexus (separate repos)

## Summary

### What We Built
1. ✅ Simple gateway (no auth/rate limiting)
2. ✅ Fast deployment (Makefile + DEPLOYMENT.md)
3. ✅ Architecture documentation
4. ✅ Migration plan

### What's Next
1. ⏳ Wait for hanzo-node v1.12.0 build
2. ⏳ Deploy gateway to DigitalOcean
3. ⏳ Configure hanzo-id to wrap gateway
4. ⏳ Set up hanzo-cloud for analytics
5. ⏳ Update hanzo-console UI

### Key Decisions
- ✅ Keep gateway simple (just proxy)
- ✅ Use hanzo-id for auth/rate limiting
- ✅ Use hanzo-cloud for analytics
- ✅ Gradual rollout (gateway first, then layers)

---

**Last Updated**: 2025-10-28
**Status**: Architecture finalized, awaiting hanzo-node release
**Next Milestone**: Gateway deployed to DigitalOcean
