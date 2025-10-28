# Hanzo Gateway - Free Tier Implementation Plan

## Overview
Gateway serves as the free plan entry point for Hanzo AI, providing anonymous IP-based access to AI inference without requiring login.

## Free vs Paid Architecture

### Free Plan (Gateway)
- **Entry Point**: gateway.hanzo.ai
- **Authentication**: None (anonymous, IP-based)
- **Features**:
  - Cloud inference routing (OpenAI, Anthropic, local providers)
  - LocalXpose-like endpoint creation for node operators
  - Desktop app connectivity
  - Usage tracking per IP
  - Rate limiting per IP
- **Cost**: Free with usage limits

### Paid Plan (Console + Cloud)
- **Entry Point**: console.hanzo.ai
- **Authentication**: Full user accounts (hanzo-id / Casdoor)
- **Features**:
  - Enhanced UI (hanzo-console frontend)
  - Advanced analytics (hanzo-cloud backend / Casibase)
  - Higher rate limits
  - Priority support
  - Custom endpoints
- **Cost**: Tiered pricing

## Free Tier Features to Implement

### 1. IP-Based Rate Limiting (Quick Implementation)
**Priority**: HIGH
**Estimated Time**: 2-4 hours

```javascript
// Simple in-memory rate limiter
const ipLimits = new Map();

const LIMITS = {
  requestsPerMinute: 10,
  requestsPerHour: 100,
  requestsPerDay: 500,
  tokensPerDay: 50000
};

function checkRateLimit(ip) {
  const now = Date.now();
  const limits = ipLimits.get(ip) || {
    minuteStart: now,
    hourStart: now,
    dayStart: now,
    minuteCount: 0,
    hourCount: 0,
    dayCount: 0,
    tokensToday: 0
  };

  // Reset counters if time windows expired
  if (now - limits.minuteStart > 60000) {
    limits.minuteCount = 0;
    limits.minuteStart = now;
  }
  if (now - limits.hourStart > 3600000) {
    limits.hourCount = 0;
    limits.hourStart = now;
  }
  if (now - limits.dayStart > 86400000) {
    limits.dayCount = 0;
    limits.tokensToday = 0;
    limits.dayStart = now;
  }

  // Check limits
  if (limits.minuteCount >= LIMITS.requestsPerMinute) {
    return { allowed: false, reason: 'Rate limit: 10 req/min exceeded' };
  }
  if (limits.hourCount >= LIMITS.requestsPerHour) {
    return { allowed: false, reason: 'Rate limit: 100 req/hour exceeded' };
  }
  if (limits.dayCount >= LIMITS.requestsPerDay) {
    return { allowed: false, reason: 'Rate limit: 500 req/day exceeded' };
  }

  // Increment counters
  limits.minuteCount++;
  limits.hourCount++;
  limits.dayCount++;
  ipLimits.set(ip, limits);

  return { allowed: true, remaining: {
    minute: LIMITS.requestsPerMinute - limits.minuteCount,
    hour: LIMITS.requestsPerHour - limits.hourCount,
    day: LIMITS.requestsPerDay - limits.dayCount
  }};
}

function updateTokenUsage(ip, tokens) {
  const limits = ipLimits.get(ip);
  if (limits) {
    limits.tokensToday += tokens;
    ipLimits.set(ip, limits);
  }
}
```

### 2. Usage Analytics per IP
**Priority**: HIGH
**Estimated Time**: 2 hours

```javascript
const usageStats = new Map();

function trackUsage(ip, model, tokens, cost) {
  const stats = usageStats.get(ip) || {
    firstSeen: new Date(),
    lastSeen: new Date(),
    totalRequests: 0,
    totalTokens: 0,
    estimatedCost: 0,
    modelUsage: {}
  };

  stats.lastSeen = new Date();
  stats.totalRequests++;
  stats.totalTokens += tokens;
  stats.estimatedCost += cost;
  stats.modelUsage[model] = (stats.modelUsage[model] || 0) + 1;

  usageStats.set(ip, stats);
}

// Endpoint to view usage (for monitoring)
app.get('/admin/usage/:ip', (req, res) => {
  const stats = usageStats.get(req.params.ip);
  res.json(stats || { error: 'No usage data' });
});
```

### 3. LocalXpose-like Endpoint Creation
**Priority**: MEDIUM
**Estimated Time**: 4-8 hours

**Concept**: Node operators with Hanzo accounts can expose their local nodes through the gateway.

```javascript
// Endpoint registry
const nodeEndpoints = new Map();

// Register a node operator endpoint
app.post('/v1/register-node', async (req, res) => {
  const { apiKey, nodeUrl, capabilities } = req.body;

  // Verify API key with hanzo-id
  const user = await verifyHanzoAPIKey(apiKey);
  if (!user) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  // Generate unique endpoint
  const endpoint = `${user.id}.node.hanzo.ai`;

  nodeEndpoints.set(endpoint, {
    userId: user.id,
    nodeUrl,
    capabilities,
    registered: new Date(),
    active: true
  });

  res.json({
    endpoint: `https://${endpoint}`,
    apiKey: apiKey, // User's existing API key
    status: 'active'
  });
});

// Route requests to node endpoints
app.all('/node/:userId/*', async (req, res) => {
  const endpoint = `${req.params.userId}.node.hanzo.ai`;
  const nodeConfig = nodeEndpoints.get(endpoint);

  if (!nodeConfig || !nodeConfig.active) {
    return res.status(404).json({ error: 'Node not found' });
  }

  // Proxy to user's local node
  const targetUrl = `${nodeConfig.nodeUrl}${req.path.replace(`/node/${req.params.userId}`, '')}`;
  // ... proxy implementation
});
```

### 4. Desktop App Integration
**Priority**: HIGH
**Estimated Time**: 1-2 hours

**Requirements**:
- Desktop apps should work with both gateway (free) and cloud (paid)
- Support `did:hanzo:gateway` identity format
- API key optional for free tier (IP-based), required for paid

```javascript
// Desktop app compatibility endpoint
app.post('/v1/desktop/connect', (req, res) => {
  const { deviceId, version, apiKey } = req.body;

  // Free tier: IP-based
  if (!apiKey) {
    const ip = req.ip || req.headers['x-forwarded-for'];
    return res.json({
      tier: 'free',
      identity: 'did:hanzo:gateway',
      limits: LIMITS,
      endpoints: {
        inference: 'https://gateway.hanzo.ai/v1/chat/completions',
        embeddings: 'https://gateway.hanzo.ai/v1/embeddings'
      }
    });
  }

  // Paid tier: API key-based
  const user = await verifyHanzoAPIKey(apiKey);
  if (user) {
    return res.json({
      tier: 'paid',
      identity: `did:hanzo:user:${user.id}`,
      limits: user.plan.limits,
      endpoints: {
        inference: 'https://api.hanzo.ai/v1/chat/completions',
        embeddings: 'https://api.hanzo.ai/v1/embeddings',
        console: 'https://console.hanzo.ai'
      }
    });
  }

  res.status(401).json({ error: 'Invalid API key' });
});
```

## Implementation Order

### Phase 1: Core Free Tier (Week 1)
1. ✅ IP-based rate limiting
2. ✅ Usage tracking per IP
3. ✅ Desktop app connectivity
4. ✅ Update README with free tier details

### Phase 2: Node Operator Features (Week 2)
1. ⏳ API key verification with hanzo-id
2. ⏳ Node endpoint registration
3. ⏳ Proxy routing to local nodes
4. ⏳ Node health monitoring

### Phase 3: Enhanced Features (Week 3)
1. ⏳ Redis-based rate limiting (for multi-instance)
2. ⏳ PostgreSQL usage analytics
3. ⏳ Grafana dashboards
4. ⏳ Admin API for monitoring

### Phase 4: Production Hardening (Week 4)
1. ⏳ DDoS protection
2. ⏳ SSL/TLS everywhere
3. ⏳ Load balancing
4. ⏳ Auto-scaling

## Technical Stack

### Current (Simple)
- Node.js HTTP server
- In-memory rate limiting
- Direct proxy to providers

### Production (Scalable)
- Redis for rate limiting (shared state)
- PostgreSQL for usage analytics
- Nginx for load balancing
- Docker Swarm or Kubernetes

## Configuration

### Environment Variables
```bash
# Free Tier Limits
FREE_TIER_REQUESTS_PER_MINUTE=10
FREE_TIER_REQUESTS_PER_HOUR=100
FREE_TIER_REQUESTS_PER_DAY=500
FREE_TIER_TOKENS_PER_DAY=50000

# Node Operator Features
ENABLE_NODE_REGISTRATION=true
NODE_VERIFICATION_URL=https://id.hanzo.ai/api/verify

# Storage
REDIS_URL=redis://localhost:6379
DATABASE_URL=postgresql://user:pass@localhost:5432/hanzo_gateway

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
```

## API Endpoints

### Public (Free Tier)
- `GET /health` - Health check
- `GET /v1/models` - List available models
- `POST /v1/chat/completions` - Inference (IP rate limited)
- `POST /v1/embeddings` - Embeddings (IP rate limited)
- `GET /v1/rate-limit-status` - Check current limits for IP

### Node Operators
- `POST /v1/register-node` - Register node endpoint
- `DELETE /v1/register-node/:id` - Unregister node
- `GET /v1/node/:userId/*` - Proxy to user's node

### Admin (Internal)
- `GET /admin/usage/:ip` - View IP usage stats
- `GET /admin/nodes` - List all registered nodes
- `POST /admin/nodes/:id/disable` - Disable node endpoint

## Monitoring & Alerts

### Key Metrics
- Requests per IP per minute/hour/day
- Token usage per IP
- Provider costs
- Rate limit violations
- Node endpoint availability

### Alerts
- High rate limit violations (potential abuse)
- Unusual token usage patterns
- Node endpoints going offline
- Provider API errors

## Security Considerations

1. **DDoS Protection**
   - Cloudflare or similar CDN
   - IP reputation checking
   - Progressive rate limiting

2. **Abuse Prevention**
   - Pattern detection for bot traffic
   - CAPTCHA for suspicious IPs
   - Automatic IP banning for severe abuse

3. **Data Privacy**
   - No logging of request content
   - Anonymized usage statistics
   - GDPR compliance

4. **Node Operator Security**
   - API key verification through hanzo-id
   - SSL/TLS for all node connections
   - Health checks and automatic failover

## Cost Estimates

### Free Tier (per 1000 users)
- Compute: $50/month (2-core VPS)
- Redis: $10/month (managed)
- PostgreSQL: $15/month (managed)
- Bandwidth: $20/month
- **Total**: ~$95/month

### With Node Operators (per 1000 operators)
- Additional compute: $100/month
- Load balancer: $20/month
- **Total**: ~$215/month

## Success Metrics

### User Adoption
- Free tier signups (IP-based usage)
- Conversion to paid plans
- Node operator registrations

### Usage
- Average requests per IP
- Token usage distribution
- Provider preference

### Performance
- Average response time
- 99th percentile latency
- Uptime percentage

## Next Steps

1. **Immediate** (This Week):
   - Implement IP-based rate limiting
   - Add usage tracking
   - Deploy to staging

2. **Short Term** (Next 2 Weeks):
   - Node operator registration
   - API key verification
   - Production deployment

3. **Long Term** (Next Month):
   - Redis-based rate limiting
   - PostgreSQL analytics
   - Admin dashboard
   - Marketing launch

## Questions & Decisions

- [ ] Should free tier require email for abuse prevention?
- [ ] What's the conversion rate target (free → paid)?
- [ ] Should we offer free trial of paid features?
- [ ] How to handle high-value node operators?
- [ ] Redis vs in-memory for rate limiting?
- [ ] When to require CAPTCHA?

---

**Status**: Draft - awaiting review
**Last Updated**: 2025-10-28
**Owner**: Gateway Team
