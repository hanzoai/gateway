#!/usr/bin/env node

/**
 * Hanzo AI Gateway - Production Proxy Server
 * Routes requests to inference backends
 */

const http = require('http');

const PORT = process.env.PORT || 3030;
const HOST = process.env.HOST || '0.0.0.0';
const GATEWAY_IDENTITY = process.env.GATEWAY_IDENTITY || 'did:hanzo:gateway';

// Backend configuration
const BACKENDS = {
  digitalocean: process.env.DO_INFERENCE_URL || 'https://inference.do-ai.run/v1',
  hanzo: process.env.HANZO_NODE_URL || 'http://localhost:9550/v2',
};

const DO_API_KEY = process.env.DIGITALOCEAN_API_KEY;

console.log('🚀 Hanzo AI Gateway');
console.log(`📍 Identity: ${GATEWAY_IDENTITY}`);
console.log(`🌐 Listening on ${HOST}:${PORT}`);
console.log(`🔗 Backends: ${Object.keys(BACKENDS).join(', ')}`);
console.log('');

// Route request to appropriate backend
async function proxyRequest(req, res, body) {
  try {
    // Default to DigitalOcean backend
    const backend = BACKENDS.digitalocean;
    const path = req.url;
    
    if (!DO_API_KEY && backend.includes('do-ai.run')) {
      throw new Error('DigitalOcean API key not configured');
    }

    const response = await fetch(`${backend}${path}`, {
      method: req.method,
      headers: {
        'Authorization': DO_API_KEY ? `Bearer ${DO_API_KEY}` : '',
        'Content-Type': 'application/json',
        'X-Gateway-Identity': GATEWAY_IDENTITY,
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    const data = await response.json();
    
    res.writeHead(response.status, {
      'Content-Type': 'application/json',
      'X-Gateway-Identity': GATEWAY_IDENTITY,
    });
    res.end(JSON.stringify(data));
  } catch (error) {
    console.error('Proxy error:', error.message);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: {
        message: error.message,
        type: 'gateway_error',
      },
    }));
  }
}

// HTTP Server
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

  // Health check
  if (req.url === '/health' || req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      identity: GATEWAY_IDENTITY,
      backends: Object.keys(BACKENDS),
      timestamp: new Date().toISOString(),
    }));
    return;
  }

  // Parse request body for POST requests
  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body);
        await proxyRequest(req, res, parsed);
      } catch (error) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
  } else {
    await proxyRequest(req, res);
  }
});

server.listen(PORT, HOST, () => {
  console.log(`✅ Gateway ready at http://${HOST}:${PORT}`);
  console.log(`🏥 Health check: http://${HOST}:${PORT}/health`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('📡 SIGTERM received, closing server...');
  server.close(() => {
    console.log('👋 Server closed');
    process.exit(0);
  });
});
