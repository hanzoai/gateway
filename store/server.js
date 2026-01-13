#!/usr/bin/env node

/**
 * Hanzo Store API Server
 *
 * Provides:
 * - Tool listings and metadata
 * - Prompt templates
 * - Default configurations
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3003;
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

console.log('🏪 Hanzo Store API Server');
console.log(`📍 Listening on ${HOST}:${PORT}`);
console.log(`📁 Data directory: ${DATA_DIR}`);
console.log('');

// Default tools (built-in)
const DEFAULT_TOOLS = [
  {
    key: 'local:::__official_hanzo:::web_search',
    name: 'Web Search',
    description: 'Search the web for information',
    version: '1.0.0',
    author: 'Hanzo',
    category: 'search',
    enabled: true,
  },
  {
    key: 'local:::__official_hanzo:::code_executor',
    name: 'Code Executor',
    description: 'Execute code in a sandboxed environment',
    version: '1.0.0',
    author: 'Hanzo',
    category: 'code',
    enabled: true,
  },
  {
    key: 'local:::__official_hanzo:::file_reader',
    name: 'File Reader',
    description: 'Read files from the local filesystem',
    version: '1.0.0',
    author: 'Hanzo',
    category: 'file',
    enabled: true,
  },
  {
    key: 'local:::__official_hanzo:::calculator',
    name: 'Calculator',
    description: 'Perform mathematical calculations',
    version: '1.0.0',
    author: 'Hanzo',
    category: 'math',
    enabled: true,
  },
];

// Default prompts
const DEFAULT_PROMPTS = [
  {
    id: 'helpful_assistant',
    name: 'Helpful Assistant',
    content: 'You are a helpful AI assistant. Answer questions accurately and concisely.',
    category: 'general',
  },
  {
    id: 'code_helper',
    name: 'Code Helper',
    content: 'You are an expert programmer. Help users write, debug, and understand code.',
    category: 'coding',
  },
  {
    id: 'creative_writer',
    name: 'Creative Writer',
    content: 'You are a creative writing assistant. Help users with stories, poems, and creative content.',
    category: 'creative',
  },
];

// In-memory store (could be replaced with a database)
let tools = [...DEFAULT_TOOLS];
let prompts = [...DEFAULT_PROMPTS];

// Load data from disk if available
function loadData() {
  try {
    const toolsPath = path.join(DATA_DIR, 'tools.json');
    if (fs.existsSync(toolsPath)) {
      tools = JSON.parse(fs.readFileSync(toolsPath, 'utf8'));
      console.log(`📦 Loaded ${tools.length} tools from disk`);
    }

    const promptsPath = path.join(DATA_DIR, 'prompts.json');
    if (fs.existsSync(promptsPath)) {
      prompts = JSON.parse(fs.readFileSync(promptsPath, 'utf8'));
      console.log(`📝 Loaded ${prompts.length} prompts from disk`);
    }
  } catch (error) {
    console.error(`⚠️ Error loading data: ${error.message}`);
  }
}

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
loadData();

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

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  // Health check
  if (pathname === '/health' || pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      service: 'hanzo-store',
      tools: tools.length,
      prompts: prompts.length,
      timestamp: new Date().toISOString(),
    }));
    return;
  }

  // Get all tools
  if (pathname === '/store/tools' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ tools, total: tools.length }));
    return;
  }

  // Get default tools/prompts (for node initialization)
  if (pathname === '/store/defaults' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      tools: DEFAULT_TOOLS,
      prompts: DEFAULT_PROMPTS,
    }));
    return;
  }

  // Get tool by key
  if (pathname.startsWith('/store/tools/') && req.method === 'GET') {
    const key = decodeURIComponent(pathname.replace('/store/tools/', ''));
    const tool = tools.find(t => t.key === key);

    if (tool) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(tool));
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Tool not found' }));
    }
    return;
  }

  // Get all prompts
  if (pathname === '/store/prompts' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ prompts, total: prompts.length }));
    return;
  }

  // Search tools
  if (pathname === '/store/search' && req.method === 'GET') {
    const query = url.searchParams.get('q') || '';
    const category = url.searchParams.get('category');

    let results = tools;

    if (query) {
      const q = query.toLowerCase();
      results = results.filter(t =>
        t.name.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.key.toLowerCase().includes(q)
      );
    }

    if (category) {
      results = results.filter(t => t.category === category);
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ results, total: results.length }));
    return;
  }

  // Categories
  if (pathname === '/store/categories' && req.method === 'GET') {
    const categories = [...new Set(tools.map(t => t.category))];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ categories }));
    return;
  }

  // 404
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, HOST, () => {
  console.log(`✅ Store API ready at http://${HOST}:${PORT}`);
  console.log(`🏥 Health: http://${HOST}:${PORT}/health`);
  console.log(`📦 Tools: http://${HOST}:${PORT}/store/tools`);
  console.log(`📝 Prompts: http://${HOST}:${PORT}/store/prompts`);
  console.log(`🔍 Search: http://${HOST}:${PORT}/store/search?q=...`);
  console.log('');
});

process.on('SIGTERM', () => {
  console.log('📡 SIGTERM received, closing server...');
  server.close(() => process.exit(0));
});
