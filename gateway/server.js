#!/usr/bin/env node

/**
 * Hanzo AI Gateway - Production Server
 *
 * Features:
 * - DigitalOcean Gradient AI Platform integration
 * - Chat completions (alibaba-qwen3-32b, llama3.3-70b-instruct, etc.)
 * - Embeddings (Alibaba-NLP/gte-large-en-v1.5, sentence-transformers)
 * - IP-based rate limiting
 * - Usage tracking
 * - Cloudflare real IP support
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

// DigitalOcean API configuration
const DO_API_KEY = process.env.DIGITALOCEAN_API_KEY;
const DO_API_URL = 'https://inference.do-ai.run/v1';

// Default embedding model (DigitalOcean)
const DEFAULT_EMBEDDING_MODEL = 'Alibaba-NLP/gte-large-en-v1.5';

// In-memory rate limiting (use Redis in production)
const ipLimits = new Map();
const usageStats = new Map();

console.log('🚀 Hanzo AI Gateway (Production)');
console.log(`📍 Identity: ${GATEWAY_IDENTITY}`);
console.log(`🌐 Listening on ${HOST}:${PORT}`);
console.log(`☁️  Cloudflare IP: ${TRUST_PROXY ? 'enabled' : 'disabled'}`);
console.log(`🔗 Provider: DigitalOcean Gradient AI`);
console.log(`📊 Limits: ${LIMITS.requestsPerDay} req/day, ${LIMITS.tokensPerDay} tokens/day`);
if (DO_API_KEY) {
  console.log(`🔑 DO API Key: sk-do-***${DO_API_KEY.slice(-10)}`);
} else {
  console.log(`⚠️  No DO API Key configured`);
}
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
function trackUsage(ip, endpoint, tokens, latencyMs) {
  const stats = usageStats.get(ip) || {
    firstSeen: new Date(),
    lastSeen: new Date(),
    totalRequests: 0,
    totalTokens: 0,
    endpoints: {},
    avgLatency: 0,
  };

  stats.lastSeen = new Date();
  stats.totalRequests++;
  stats.totalTokens += tokens;
  stats.endpoints[endpoint] = (stats.endpoints[endpoint] || 0) + 1;
  stats.avgLatency = (stats.avgLatency * (stats.totalRequests - 1) + latencyMs) / stats.totalRequests;

  usageStats.set(ip, stats);
}

/**
 * Handle chat completions
 */
async function handleChatCompletions(req, res, body, ip) {
  const startTime = Date.now();

  if (!DO_API_KEY) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: {
        message: 'DigitalOcean API key not configured',
        type: 'configuration_error',
      },
    }));
    return;
  }

  try {
    const model = body.model || 'alibaba-qwen3-32b';
    console.log(`📨 ${ip} → Chat (${model})`);

    const response = await fetch(`${DO_API_URL}/chat/completions`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${DO_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`DigitalOcean API error (${response.status}): ${error}`);
    }

    const data = await response.json();
    const latency = Date.now() - startTime;

    // Extract token usage
    const tokens = data.usage?.total_tokens || 0;
    updateTokenUsage(ip, tokens);
    trackUsage(ip, 'chat', tokens, latency);

    console.log(`✅ ${ip} → Chat: ${tokens} tokens, ${latency}ms`);

    // Return response with rate limit headers
    const rateLimitStatus = ipLimits.get(ip);
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-Gateway-Identity': GATEWAY_IDENTITY,
      'X-Provider': 'digitalocean',
      'X-RateLimit-Limit-Day': LIMITS.requestsPerDay.toString(),
      'X-RateLimit-Remaining-Day': (LIMITS.requestsPerDay - (rateLimitStatus?.dayCount || 0)).toString(),
      'X-RateLimit-Remaining-Tokens': (LIMITS.tokensPerDay - (rateLimitStatus?.tokensToday || 0)).toString(),
    });
    res.end(JSON.stringify(data));

  } catch (error) {
    const latency = Date.now() - startTime;
    console.error(`❌ ${ip} chat error: ${error.message} (${latency}ms)`);

    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: {
        message: error.message,
        type: 'gateway_error',
        provider: 'digitalocean',
      },
    }));
  }
}

/**
 * Handle embeddings
 */
async function handleEmbeddings(req, res, body, ip) {
  const startTime = Date.now();

  if (!DO_API_KEY) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: {
        message: 'DigitalOcean API key not configured',
        type: 'configuration_error',
      },
    }));
    return;
  }

  try {
    const model = body.model || DEFAULT_EMBEDDING_MODEL;
    const input = body.input;

    if (!input) {
      throw new Error('Missing required field: input');
    }

    console.log(`📨 ${ip} → Embeddings (${model})`);

    const response = await fetch(`${DO_API_URL}/embeddings`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${DO_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ model, input }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`DigitalOcean API error (${response.status}): ${error}`);
    }

    const data = await response.json();
    const latency = Date.now() - startTime;

    // Estimate tokens (embeddings don't return usage)
    const textLength = Array.isArray(input) ? input.join(' ').length : input.length;
    const estimatedTokens = Math.ceil(textLength / 4);

    updateTokenUsage(ip, estimatedTokens);
    trackUsage(ip, 'embeddings', estimatedTokens, latency);

    console.log(`✅ ${ip} → Embeddings: ~${estimatedTokens} tokens, ${latency}ms`);

    const rateLimitStatus = ipLimits.get(ip);
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-Gateway-Identity': GATEWAY_IDENTITY,
      'X-Provider': 'digitalocean',
      'X-RateLimit-Limit-Day': LIMITS.requestsPerDay.toString(),
      'X-RateLimit-Remaining-Day': (LIMITS.requestsPerDay - (rateLimitStatus?.dayCount || 0)).toString(),
      'X-RateLimit-Remaining-Tokens': (LIMITS.tokensPerDay - (rateLimitStatus?.tokensToday || 0)).toString(),
    });
    res.end(JSON.stringify(data));

  } catch (error) {
    const latency = Date.now() - startTime;
    console.error(`❌ ${ip} embeddings error: ${error.message} (${latency}ms)`);

    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: {
        message: error.message,
        type: 'gateway_error',
        provider: 'digitalocean',
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
      provider: 'digitalocean',
      configured: !!DO_API_KEY,
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
      ip: ip.replace(/:\d+$/, ''),
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
      // Chat models
      { id: 'alibaba-qwen3-32b', type: 'chat', provider: 'digitalocean', pricing: '$0.30/1M tokens' },
      { id: 'llama3.3-70b-instruct', type: 'chat', provider: 'digitalocean', pricing: '$0.60/1M tokens' },
      { id: 'llama3-8b-instruct', type: 'chat', provider: 'digitalocean', pricing: '$0.30/1M tokens' },
      { id: 'mistral-nemo-instruct-2407', type: 'chat', provider: 'digitalocean', pricing: '$0.30/1M tokens' },
      { id: 'deepseek-r1-distill-llama-70b', type: 'chat', provider: 'digitalocean', pricing: '$0.60/1M tokens' },
      // Embedding models
      { id: 'Alibaba-NLP/gte-large-en-v1.5', type: 'embedding', provider: 'digitalocean', pricing: 'Free tier', parameters: '434M' },
      { id: 'sentence-transformers/all-MiniLM-L6-v2', type: 'embedding', provider: 'digitalocean', pricing: 'Free tier', parameters: '22.7M' },
      { id: 'sentence-transformers/multi-qa-mpnet-base-dot-v1', type: 'embedding', provider: 'digitalocean', pricing: 'Free tier', parameters: '109M' },
    ];

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ data: models, object: 'list' }));
    return;
  }

  // Chat completions
  if (req.url === '/v1/chat/completions' && req.method === 'POST') {
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

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body);
        await handleChatCompletions(req, res, parsed, ip);
      } catch (error) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  // Embeddings
  if (req.url === '/v1/embeddings' && req.method === 'POST') {
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

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body);
        await handleEmbeddings(req, res, parsed, ip);
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
  console.log(`🔢 Embeddings: http://${HOST}:${PORT}/v1/embeddings`);
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
