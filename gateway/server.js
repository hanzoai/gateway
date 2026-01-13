#!/usr/bin/env node

/**
 * Hanzo AI Gateway - Enhanced Production Server
 * 
 * Features:
 * - Cloudflare real IP extraction
 * - IP-based rate limiting (free tier)
 * - Multi-provider routing (DeepSeek, OpenAI, Anthropic, DigitalOcean)
 * - Optional local node fallback
 * - Usage tracking
 */

const http = require('http');

// Configuration
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';
const GATEWAY_IDENTITY = process.env.GATEWAY_IDENTITY || 'did:hanzo:gateway';

// Cloudflare IP extraction
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const CF_IP_HEADER = process.env.CF_CONNECTING_IP_HEADER || 'CF-Connecting-IP';

// Free tier limits
const LIMITS = {
  requestsPerMinute: parseInt(process.env.FREE_TIER_REQUESTS_PER_MINUTE || '10'),
  requestsPerHour: parseInt(process.env.FREE_TIER_REQUESTS_PER_HOUR || '100'),
  requestsPerDay: parseInt(process.env.FREE_TIER_REQUESTS_PER_DAY || '500'),
  tokensPerDay: parseInt(process.env.FREE_TIER_TOKENS_PER_DAY || '50000'),
};

// Provider backends
const PROVIDERS = {
  deepseek: {
    url: 'https://api.deepseek.com/v1',
    key: process.env.DEEPSEEK_API_KEY,
  },
  openai: {
    url: 'https://api.openai.com/v1',
    key: process.env.OPENAI_API_KEY,
  },
  anthropic: {
    url: 'https://api.anthropic.com/v1',
    key: process.env.ANTHROPIC_API_KEY,
  },
  digitalocean: {
    url: 'https://inference.do-ai.run/v1',
    key: process.env.DIGITALOCEAN_API_KEY,
  },
  local: {
    url: process.env.LOCAL_NODE_URL || 'http://localhost:8000',
    key: null,
  },
};

// Default provider
const DEFAULT_PROVIDER = 'deepseek';

// In-memory rate limiting (use Redis in production)
const ipLimits = new Map();
const usageStats = new Map();

console.log('🚀 Hanzo AI Gateway (Enhanced)');
console.log(`📍 Identity: ${GATEWAY_IDENTITY}`);
console.log(`🌐 Listening on ${HOST}:${PORT}`);
console.log(`☁️  Cloudflare IP: ${TRUST_PROXY ? 'enabled' : 'disabled'}`);
console.log(`🔗 Providers: ${Object.keys(PROVIDERS).filter(k => PROVIDERS[k].key || k === 'local').join(', ')}`);
console.log(`📊 Limits: ${LIMITS.requestsPerDay} req/day, ${LIMITS.tokensPerDay} tokens/day`);
console.log('');

/**
 * Extract real IP address from request
 */
function getRealIP(req) {
  if (TRUST_PROXY) {
    // Check Cloudflare header first
    const cfIP = req.headers[CF_IP_HEADER.toLowerCase()];
    if (cfIP) return cfIP;
    
    // Check X-Forwarded-For
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
    
    // Check X-Real-IP
    const realIP = req.headers['x-real-ip'];
    if (realIP) return realIP;
  }
  
  // Fallback to socket
  return req.socket.remoteAddress || 'unknown';
}

/**
 * Check rate limits for an IP
 */
function checkRateLimit(ip) {
  const now = Date.now();
  const limits = ipLimits.get(ip) || {
    minuteStart: now,
    hourStart: now,
    dayStart: now,
    minuteCount: 0,
    hourCount: 0,
    dayCount: 0,
    tokensToday: 0,
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
    return {
      allowed: false,
      reason: `Rate limit: ${LIMITS.requestsPerMinute} req/min exceeded`,
      resetIn: 60 - Math.floor((now - limits.minuteStart) / 1000),
    };
  }
  if (limits.hourCount >= LIMITS.requestsPerHour) {
    return {
      allowed: false,
      reason: `Rate limit: ${LIMITS.requestsPerHour} req/hour exceeded`,
      resetIn: 3600 - Math.floor((now - limits.hourStart) / 1000),
    };
  }
  if (limits.dayCount >= LIMITS.requestsPerDay) {
    return {
      allowed: false,
      reason: `Rate limit: ${LIMITS.requestsPerDay} req/day exceeded`,
      resetIn: 86400 - Math.floor((now - limits.dayStart) / 1000),
    };
  }
  if (limits.tokensToday >= LIMITS.tokensPerDay) {
    return {
      allowed: false,
      reason: `Token limit: ${LIMITS.tokensPerDay} tokens/day exceeded`,
      resetIn: 86400 - Math.floor((now - limits.dayStart) / 1000),
    };
  }

  // Increment counters
  limits.minuteCount++;
  limits.hourCount++;
  limits.dayCount++;
  ipLimits.set(ip, limits);

  return {
    allowed: true,
    remaining: {
      minute: LIMITS.requestsPerMinute - limits.minuteCount,
      hour: LIMITS.requestsPerHour - limits.hourCount,
      day: LIMITS.requestsPerDay - limits.dayCount,
      tokens: LIMITS.tokensPerDay - limits.tokensToday,
    },
  };
}

/**
 * Update token usage for an IP
 */
function updateTokenUsage(ip, tokens) {
  const limits = ipLimits.get(ip);
  if (limits) {
    limits.tokensToday += tokens;
    ipLimits.set(ip, limits);
  }
}

/**
 * Track usage statistics
 */
function trackUsage(ip, model, tokens, latencyMs) {
  const stats = usageStats.get(ip) || {
    firstSeen: new Date(),
    lastSeen: new Date(),
    totalRequests: 0,
    totalTokens: 0,
    modelUsage: {},
    avgLatency: 0,
  };

  stats.lastSeen = new Date();
  stats.totalRequests++;
  stats.totalTokens += tokens;
  stats.modelUsage[model] = (stats.modelUsage[model] || 0) + 1;
  stats.avgLatency = (stats.avgLatency * (stats.totalRequests - 1) + latencyMs) / stats.totalRequests;

  usageStats.set(ip, stats);
}

/**
 * Determine provider from model name
 */
function getProviderForModel(model) {
  if (model.startsWith('deepseek-')) return 'deepseek';
  if (model.startsWith('gpt-')) return 'openai';
  if (model.startsWith('claude-')) return 'anthropic';
  if (model.startsWith('qwen') || model.startsWith('zen-')) return 'local';
  
  // Default to DeepSeek for unknown models
  return DEFAULT_PROVIDER;
}

/**
 * Route request to appropriate provider
 */
async function proxyToProvider(req, res, body, ip) {
  const startTime = Date.now();
  
  try {
    // Determine provider
    const model = body.model || 'deepseek-chat';
    const providerName = getProviderForModel(model);
    const provider = PROVIDERS[providerName];

    if (!provider) {
      throw new Error(`Provider ${providerName} not configured`);
    }

    if (!provider.key && providerName !== 'local') {
      throw new Error(`API key for ${providerName} not configured`);
    }

    // Build target URL
    const path = req.url;
    const targetURL = `${provider.url}${path}`;

    console.log(`📨 ${ip} → ${providerName} (${model})`);

    // Build headers
    const headers = {
      'Content-Type': 'application/json',
      'X-Gateway-Identity': GATEWAY_IDENTITY,
    };

    if (provider.key) {
      if (providerName === 'anthropic') {
        headers['x-api-key'] = provider.key;
        headers['anthropic-version'] = '2023-06-01';
      } else {
        headers['Authorization'] = `Bearer ${provider.key}`;
      }
    }

    // Forward request
    const response = await fetch(targetURL, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Provider error (${response.status}): ${error}`);
    }

    const data = await response.json();
    const latency = Date.now() - startTime;

    // Extract token usage
    const tokens = data.usage?.total_tokens || 0;
    updateTokenUsage(ip, tokens);
    trackUsage(ip, model, tokens, latency);

    console.log(`✅ ${ip} → ${providerName}: ${tokens} tokens, ${latency}ms`);

    // Return response with rate limit headers
    const rateLimitStatus = ipLimits.get(ip);
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-Gateway-Identity': GATEWAY_IDENTITY,
      'X-Provider': providerName,
      'X-RateLimit-Limit-Day': LIMITS.requestsPerDay.toString(),
      'X-RateLimit-Remaining-Day': (LIMITS.requestsPerDay - (rateLimitStatus?.dayCount || 0)).toString(),
      'X-RateLimit-Remaining-Tokens': (LIMITS.tokensPerDay - (rateLimitStatus?.tokensToday || 0)).toString(),
    });
    res.end(JSON.stringify(data));

  } catch (error) {
    const latency = Date.now() - startTime;
    console.error(`❌ ${ip} error: ${error.message} (${latency}ms)`);
    
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: {
        message: error.message,
        type: 'gateway_error',
        provider: error.provider || 'unknown',
      },
    }));
  }
}

/**
 * HTTP Server
 */
const server = http.createServer(async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Extract real IP
  const ip = getRealIP(req);

  // Health check
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      identity: GATEWAY_IDENTITY,
      providers: Object.keys(PROVIDERS).filter(k => PROVIDERS[k].key || k === 'local'),
      limits: LIMITS,
      cloudflare: TRUST_PROXY,
      timestamp: new Date().toISOString(),
    }));
    return;
  }

  // Rate limit status
  if (req.url === '/v1/rate-limit-status') {
    const limits = ipLimits.get(ip);
    const stats = usageStats.get(ip);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ip: ip.replace(/:\d+$/, ''), // Remove port if present
      limits: {
        requestsPerMinute: LIMITS.requestsPerMinute,
        requestsPerHour: LIMITS.requestsPerHour,
        requestsPerDay: LIMITS.requestsPerDay,
        tokensPerDay: LIMITS.tokensPerDay,
      },
      usage: limits ? {
        minuteCount: limits.minuteCount,
        hourCount: limits.hourCount,
        dayCount: limits.dayCount,
        tokensToday: limits.tokensToday,
      } : { minuteCount: 0, hourCount: 0, dayCount: 0, tokensToday: 0 },
      stats: stats || { totalRequests: 0, totalTokens: 0 },
    }));
    return;
  }

  // Models list
  if (req.url === '/v1/models' && req.method === 'GET') {
    const models = [
      // DeepSeek
      { id: 'deepseek-chat', provider: 'deepseek', pricing: 'Free tier' },
      { id: 'deepseek-coder', provider: 'deepseek', pricing: 'Free tier' },
      // OpenAI
      ...(PROVIDERS.openai.key ? [
        { id: 'gpt-4', provider: 'openai', pricing: 'Free tier' },
        { id: 'gpt-3.5-turbo', provider: 'openai', pricing: 'Free tier' },
      ] : []),
      // Anthropic
      ...(PROVIDERS.anthropic.key ? [
        { id: 'claude-3-opus', provider: 'anthropic', pricing: 'Free tier' },
        { id: 'claude-3-sonnet', provider: 'anthropic', pricing: 'Free tier' },
      ] : []),
      // Local
      { id: 'qwen3-32b', provider: 'local', pricing: 'Free (local)' },
      { id: 'zen-coder-30b', provider: 'local', pricing: 'Free (local)' },
    ];

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ data: models, object: 'list' }));
    return;
  }

  // Chat completions
  if (req.url === '/v1/chat/completions' && req.method === 'POST') {
    // Check rate limit
    const rateLimitCheck = checkRateLimit(ip);
    if (!rateLimitCheck.allowed) {
      res.writeHead(429, { 
        'Content-Type': 'application/json',
        'X-RateLimit-Reset': rateLimitCheck.resetIn.toString(),
      });
      res.end(JSON.stringify({
        error: {
          message: rateLimitCheck.reason,
          type: 'rate_limit_exceeded',
          reset_in_seconds: rateLimitCheck.resetIn,
        },
      }));
      return;
    }

    // Parse and proxy request
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body);
        await proxyToProvider(req, res, parsed, ip);
      } catch (error) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  // 404
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, HOST, () => {
  console.log(`✅ Gateway ready at http://${HOST}:${PORT}`);
  console.log(`🏥 Health: http://${HOST}:${PORT}/health`);
  console.log(`📊 Models: http://${HOST}:${PORT}/v1/models`);
  console.log(`💬 Chat: http://${HOST}:${PORT}/v1/chat/completions`);
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('📡 SIGTERM received, closing server...');
  server.close(() => {
    console.log('👋 Server closed');
    process.exit(0);
  });
});
