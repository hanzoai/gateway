# Contributing to Hanzo Gateway

Thank you for considering contributing to Hanzo Gateway! This document outlines the process and guidelines.

## 🚀 Quick Start

1. **Fork the repository**
2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/inference.git
   cd inference
   ```
3. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Make your changes**
5. **Test your changes**
   ```bash
   cd gateway
   npm test
   ```
6. **Commit and push**
   ```bash
   git add .
   git commit -m "feat: your feature description"
   git push origin feature/your-feature-name
   ```
7. **Open a Pull Request**

## 📋 Development Setup

### Prerequisites

- Node.js 20+ (for gateway)
- Docker & Docker Compose
- Git
- API keys for testing (DigitalOcean, OpenAI, or Claude)

### Local Development

```bash
# Clone repo
git clone https://github.com/hanzoai/inference.git
cd inference

# Gateway setup
cd gateway
npm install
cp .env.example .env
# Add your test API keys to .env
npm start

# Run tests
npm test
```

## 🧪 Testing

### Running Tests

```bash
# All tests
npm test

# Specific test file
node test/api.test.js

# With coverage
npm run test:coverage
```

### Writing Tests

Tests should cover:
- API endpoint functionality
- Rate limiting behavior
- Cost tracking
- Error handling
- Provider failover

Example test:
```javascript
async function testNewFeature() {
  console.log('\n🧪 Test New Feature');
  
  const response = await fetch(`${BASE_URL}/your-endpoint`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ test: 'data' })
  });
  
  assert(response.status === 200, '✅ Status code is 200');
  const data = await response.json();
  assert(data.success, '✅ Response indicates success');
  console.log('✅ Test passed');
}
```

## 📝 Code Style

### JavaScript/Node.js (Gateway)

- Use ES6+ features
- Async/await over callbacks
- Clear variable names
- Comment complex logic
- Error handling required

Example:
```javascript
async function processInference(model, messages) {
  try {
    // Clear intent
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ model, messages })
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Inference failed:', error);
    throw error;
  }
}
```

### Rust (Cloud Node)

- Follow Rust conventions
- Use `rustfmt` for formatting
- Use `clippy` for linting
- Add documentation comments
- Handle errors explicitly

## 🔀 Branch Strategy

- `main` - Production-ready code
- `develop` - Integration branch
- `feature/*` - New features
- `fix/*` - Bug fixes
- `docs/*` - Documentation updates

## 💬 Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Qwen3 model support
fix: resolve rate limiting edge case
docs: update API documentation
test: add provider failover tests
chore: update dependencies
```

## 🐛 Reporting Bugs

Use GitHub Issues with this template:

**Bug Description:**
Clear description of the bug

**Steps to Reproduce:**
1. Step 1
2. Step 2
3. See error

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Environment:**
- OS: macOS 14.0
- Node: 20.10.0
- Docker: 24.0.0

**Logs:**
```
Relevant log output
```

## 💡 Feature Requests

Use GitHub Issues with this template:

**Feature Description:**
Clear description of the proposed feature

**Use Case:**
Why this feature is needed

**Proposed Solution:**
How you envision this working

**Alternatives Considered:**
Other approaches you've thought about

## 🔐 Security

Report security vulnerabilities to security@hanzo.ai (not in public issues).

## 📄 License

By contributing, you agree your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be added to our [CONTRIBUTORS.md](./CONTRIBUTORS.md) file.

## 📞 Questions?

- **Discord**: https://discord.gg/hanzo
- **Email**: dev@hanzo.ai
- **Discussions**: https://github.com/hanzoai/inference/discussions

Thank you for contributing to Hanzo Gateway! 🚀
