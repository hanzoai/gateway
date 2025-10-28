#!/usr/bin/env node

/**
 * API Tests for Hanzo Gateway
 */

require('dotenv').config();

const DO_API_KEY = process.env.DIGITALOCEAN_API_KEY;
const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3001';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✅ ${message}`);
    passed++;
  } else {
    console.log(`  ❌ ${message}`);
    failed++;
  }
}

async function test(name, fn) {
  console.log(`\n🧪 ${name}`);
  try {
    await fn();
  } catch (error) {
    console.log(`  ❌ Test failed: ${error.message}`);
    failed++;
  }
}

async function testHealthEndpoint() {
  const response = await fetch(`${BASE_URL}/health`);
  const data = await response.json();
  
  assert(response.status === 200, 'Status code is 200');
  assert(data.status === 'healthy', 'Status is healthy');
  assert(data.service === 'inference', 'Service name is inference');
  assert(data.version, 'Version is present');
}

async function testListModels() {
  const response = await fetch(`${BASE_URL}/v1/models`);
  const data = await response.json();
  
  assert(response.status === 200, 'Status code is 200');
  assert(Array.isArray(data.data), 'Data is an array');
  assert(data.data.length > 0, 'Models list is not empty');
  assert(data.data[0].id, 'Model has id');
  assert(data.data[0].owned_by, 'Model has owned_by');
  
  console.log(`  📊 Found ${data.data.length} models`);
}

async function testChatCompletions() {
  const response = await fetch(`${BASE_URL}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'llama3-8b-instruct',
      messages: [
        { role: 'user', content: 'Say "Hello, Hanzo!" and nothing else.' }
      ],
      max_tokens: 20,
      temperature: 0.1
    })
  });
  
  const data = await response.json();
  
  assert(response.status === 200, 'Status code is 200');
  assert(data.choices, 'Response has choices');
  assert(data.choices.length > 0, 'Choices array is not empty');
  assert(data.choices[0].message, 'First choice has message');
  assert(data.choices[0].message.content, 'Message has content');
  assert(data.usage, 'Response has usage data');
  assert(data.usage.total_tokens > 0, 'Total tokens > 0');
  
  console.log(`  💬 Response: "${data.choices[0].message.content.slice(0, 50)}..."`);
  console.log(`  📊 Tokens: ${data.usage.total_tokens} (${data.usage.prompt_tokens} + ${data.usage.completion_tokens})`);
}

async function testDirectDOAPI() {
  const response = await fetch('https://inference.do-ai.run/v1/models', {
    headers: {
      'Authorization': `Bearer ${DO_API_KEY}`,
      'Content-Type': 'application/json'
    }
  });
  
  const data = await response.json();
  
  assert(response.status === 200, 'DO API returns 200');
  assert(Array.isArray(data.data), 'DO API returns array');
  assert(data.data.length > 0, 'DO API returns models');
  
  console.log(`  🌐 DigitalOcean API: ${data.data.length} models available`);
}

async function testDirectInference() {
  const response = await fetch('https://inference.do-ai.run/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${DO_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: 'llama3-8b-instruct',
      messages: [{ role: 'user', content: 'Hi' }],
      max_tokens: 10
    })
  });
  
  const data = await response.json();
  
  assert(response.status === 200, 'Direct inference works');
  assert(data.choices && data.choices.length > 0, 'Has response');
  
  console.log(`  💬 Direct DO response: "${data.choices[0].message.content}"`);
}

async function testAllModels() {
  // Test a few different models
  const models = [
    'llama3-8b-instruct',
    'mistral-nemo-instruct-2407'
  ];
  
  for (const model of models) {
    const response = await fetch('https://inference.do-ai.run/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${DO_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: 'Hi' }],
        max_tokens: 5
      })
    });
    
    const data = await response.json();
    assert(response.status === 200, `${model} works`);
  }
}

async function runAllTests() {
  console.log('🚀 Hanzo AI Inference Gateway - API Tests\n');
  console.log(`📍 Base URL: ${BASE_URL}`);
  console.log(`🔑 API Key: sk-do-***${DO_API_KEY.slice(-20)}\n`);
  
  // Direct DigitalOcean API tests
  console.log('\n━━━ Direct DigitalOcean API Tests ━━━');
  await test('Test Direct DO API Connection', testDirectDOAPI);
  await test('Test Direct DO Inference', testDirectInference);
  await test('Test Multiple Models', testAllModels);
  
  // Local server tests (if running)
  console.log('\n━━━ Local Server Tests ━━━');
  try {
    await test('Test Health Endpoint', testHealthEndpoint);
    await test('Test List Models', testListModels);
    await test('Test Chat Completions', testChatCompletions);
  } catch (error) {
    console.log(`\n⚠️  Local server not running at ${BASE_URL}`);
    console.log('   Start it with: npm start');
  }
  
  // Summary
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`\n📊 Test Results:`);
  console.log(`   ✅ Passed: ${passed}`);
  console.log(`   ❌ Failed: ${failed}`);
  console.log(`   📈 Total:  ${passed + failed}`);
  
  if (failed === 0) {
    console.log(`\n🎉 All tests passed!`);
    process.exit(0);
  } else {
    console.log(`\n❌ ${failed} test(s) failed`);
    process.exit(1);
  }
}

runAllTests().catch(error => {
  console.error('\n❌ Test suite failed:', error);
  process.exit(1);
});
