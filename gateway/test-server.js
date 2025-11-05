#!/usr/bin/env node

/**
 * Hanzo AI Inference Gateway - Test Server
 * Quick local test without Docker
 */

const http = require('http');
require('dotenv').config();

const PORT = process.env.INFERENCE_PORT || 3001;
const DO_API_KEY = process.env.DIGITALOCEAN_API_KEY;

if (!DO_API_KEY) {
  console.error('❌ Error: DIGITALOCEAN_API_KEY not set in .env file');
  process.exit(1);
}

console.log('✅ DigitalOcean API key loaded');
console.log(`🔑 Key: sk-do-***${DO_API_KEY.slice(-20)}`);

// Test DigitalOcean API connection
async function testDOConnection() {
  try {
    const response = await fetch('https://inference.do-ai.run/v1/models', {
      headers: {
        'Authorization': `Bearer ${DO_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }
    
    const data = await response.json();
    console.log(`✅ Connected to DigitalOcean API`);
    console.log(`📊 Available models: ${data.data.length}`);
    console.log('');
    console.log('Top 5 models:');
    data.data.slice(0, 5).forEach(model => {
      console.log(`  - ${model.id} (${model.owned_by})`);
    });
    console.log('');
    return data.data;
  } catch (error) {
    console.error('❌ Failed to connect to DigitalOcean API:', error.message);
    process.exit(1);
  }
}

// Simple inference proxy
async function handleInference(body) {
  const response = await fetch('https://inference.do-ai.run/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${DO_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  
  if (!response.ok) {
    throw new Error(`Inference API returned ${response.status}`);
  }
  
  return await response.json();
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
  if (req.url === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'healthy',
      service: 'inference',
      version: '1.0.0',
      timestamp: new Date().toISOString()
    }));
    return;
  }
  
  // List models
  if (req.url === '/v1/models' && req.method === 'GET') {
    try {
      const response = await fetch('https://inference.do-ai.run/v1/models', {
        headers: {
          'Authorization': `Bearer ${DO_API_KEY}`,
          'Content-Type': 'application/json'
        }
      });
      const data = await response.json();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message }));
    }
    return;
  }

  // Embeddings (local Ollama fallback)
  if (req.url === '/v1/embeddings' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const requestBody = JSON.parse(body);
        console.log(`🔢 Embedding request: ${requestBody.model}`);

        // Map DO model names to equivalent local Ollama models
        // Match models by size and purpose:
        // - MiniLM (22.7M) → snowflake (110MB) - small, general
        // - mpnet (109M) → qwen3-0.6b (639MB) - medium, Q&A
        // - GTE (434M) → nomic or mxbai (274-670MB) - large, quality
        const modelMap = {
          'sentence-transformers/all-MiniLM-L6-v2': 'snowflake-arctic-embed:xs',
          'all-MiniLM-L6-v2': 'snowflake-arctic-embed:xs',
          'sentence-transformers/multi-qa-mpnet-base-dot-v1': 'qwen3-embedding:0.6b',
          'Alibaba-NLP/gte-large-en-v1.5': 'nomic-embed-text:v1.5',
        };

        const ollamaModel = modelMap[requestBody.model] || requestBody.model;

        // Proxy to local Ollama
        const ollamaResponse = await fetch('http://127.0.0.1:11435/api/embeddings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: ollamaModel,
            prompt: requestBody.input
          })
        });

        if (!ollamaResponse.ok) {
          throw new Error(`Ollama returned ${ollamaResponse.status}`);
        }

        const ollamaData = await ollamaResponse.json();

        // Convert to OpenAI format
        const result = {
          object: 'list',
          data: [{
            object: 'embedding',
            embedding: ollamaData.embedding,
            index: 0
          }],
          model: requestBody.model,
          usage: {
            prompt_tokens: ollamaData.prompt_eval_count || 0,
            total_tokens: ollamaData.prompt_eval_count || 0
          }
        };

        console.log(`✅ Embedding generated: ${result.data[0].embedding.length} dimensions`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (error) {
        console.error('❌ Embedding error:', error.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: error.message }));
      }
    });
    return;
  }

  // Chat completions
  if (req.url === '/v1/chat/completions' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const requestBody = JSON.parse(body);
        console.log(`📨 Inference request: ${requestBody.model}`);
        
        const result = await handleInference(requestBody);
        
        console.log(`✅ Response: ${result.usage.total_tokens} tokens`);
        console.log(`💬 Content: ${result.choices[0].message.content.slice(0, 100)}...`);
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (error) {
        console.error('❌ Error:', error.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: error.message }));
      }
    });
    return;
  }
  
  // 404
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

// Start server
async function start() {
  console.log('🚀 Hanzo AI Inference Gateway - Test Server');
  console.log('');
  
  // Test connection first
  await testDOConnection();
  
  server.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log('');
    console.log('Available endpoints:');
    console.log(`  GET  http://localhost:${PORT}/health`);
    console.log(`  GET  http://localhost:${PORT}/v1/models`);
    console.log(`  POST http://localhost:${PORT}/v1/chat/completions`);
    console.log('');
    console.log('Test with curl:');
    console.log(`  curl http://localhost:${PORT}/health`);
    console.log(`  curl http://localhost:${PORT}/v1/models`);
    console.log('');
    console.log('Press Ctrl+C to stop');
  });
}

start().catch(error => {
  console.error('❌ Failed to start server:', error);
  process.exit(1);
});
