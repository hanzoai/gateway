# Hanzo Ecosystem Architecture

## Overview

Hanzo provides a comprehensive AI infrastructure platform with decentralized compute, identity management, and multi-provider routing.

## Repository Structure

### Core Infrastructure

#### 1. **hanzo-gateway** (github.com/hanzoai/gateway)
**Location**: `~/work/hanzo/gateway`  
**Purpose**: Fast API gateway sitting in front of Hanzo nodes  
**Tech**: Rust (downloads pre-built binaries)

**Key Features**:
- Routes requests to any OpenAI-compatible API
- Multi-provider LLM routing
- Fast Docker builds (<30s vs 45+ min)
- Identity integration via hanzo-id
- Pure environment variable configuration

**Identity**: `did:hanzo:gateway`

#### 2. **hanzo-node** (github.com/hanzoai/node)
**Location**: `~/work/shinkai/hanzo-node`  
**Purpose**: Distributed AI node with P2P networking  
**Tech**: Rust

**Key Features**:
- Local LLM inference
- Vector embeddings
- Knowledge base (RAG)
- P2P networking (libp2p)
- Job queue management
- Model discovery

**Branches**:
- `main` - Stable releases
- `next` - Active development

#### 3. **hanzo-id** (github.com/hanzoai/id)
**Location**: `~/work/hanzo/id`  
**Purpose**: Identity and authentication management  
**Tech**: Go

**Integrations**:
- Casdoor (SSO/Auth)
- DID support
- OAuth 2.0
- JWT tokens

#### 4. **hanzo-cloud** (github.com/hanzoai/cloud)
**Location**: `~/work/hanzo/cloud`  
**Purpose**: Cloud infrastructure and orchestration  
**Tech**: Rust

**Features**:
- Node deployment
- Service mesh
- Load balancing
- Monitoring

#### 5. **rust-sdk** (github.com/hanzoai/rust-sdk)
**Location**: `~/work/hanzo/rust-sdk`  
**Purpose**: Shared Rust crates for all Hanzo projects  
**Tech**: Rust workspace

**Current Crates**:
- ✅ hanzo-config
- ✅ hanzo-crypto
- ✅ hanzo-message-primitives
- ✅ hanzo-pqc

**To Add** (from hanzo-node & universe):
- hanzo-did - DID support
- hanzo-mcp - Model Context Protocol
- hanzo-model-discovery - AI model registry
- hanzo-db - Database utilities
- hanzo-kbs - Knowledge base system
- hanzo-embedding - Vector embeddings
- hanzo-fs - Filesystem utilities
- hanzo-http-api - HTTP/REST utilities
- hanzo-sqlite - SQLite wrappers
- hanzo-baml - BAML support
- hanzo-hmm - HMM utilities

**Client Library** (mirrors python-sdk):
- hanzo-client - Main client SDK
- hanzo-aci - AI Chain Infrastructure client
- hanzo-agents - Agent framework
- hanzo-network - Networking client
- hanzo-memory - Memory management
- hanzo-repl - REPL interface

#### 6. **python-sdk** (github.com/hanzoai/python-sdk)
**Location**: `~/work/hanzo/python-sdk`  
**Purpose**: Comprehensive Python SDK  
**Tech**: Python (uv workspace)

**Packages** (`pkg/`):
- `hanzo` - Core SDK
- `hanzo-aci` - AI Chain Infrastructure
- `hanzo-agents` - Agent framework
- `hanzo-mcp` - Model Context Protocol
- `hanzo-memory` - Memory systems
- `hanzo-network` - P2P networking
- `hanzo-repl` - REPL
- `hanzoai` - Main client library

#### 7. **engine** (github.com/hanzoai/engine)
**Location**: `~/work/hanzo/engine`  
**Purpose**: LLM inference engine (mistral.rs fork)  
**Tech**: Rust

**Features**:
- Local model inference
- GGUF support
- Quantization
- CUDA/ROCm acceleration

### Upstream Dependencies

#### Casbin Ecosystem (~/work/cas/)

1. **casdoor** - Authentication & SSO
   - OAuth 2.0 provider
   - SAML support
   - LDAP integration
   - Used by: hanzo-id, hanzo-cloud

2. **casibase** - AI Knowledge Base
   - Vector storage
   - Semantic search
   - RAG support
   - Used by: hanzo-node, hanzo-cloud

3. **casvisor** - Monitoring & Visualization
   - Service monitoring
   - Metrics collection
   - Dashboards
   - Used by: hanzo-cloud

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Client Applications                   │
│  (Desktop, Web, Mobile, CLI)                            │
└───────────────────┬─────────────────────────────────────┘
                    │
                    │ HTTPS/gRPC
                    │
┌───────────────────▼─────────────────────────────────────┐
│              hanzo-gateway (did:hanzo:gateway)          │
│  - OpenAI-compatible API                                │
│  - Multi-provider routing                               │
│  - Authentication (via hanzo-id)                        │
│  - Rate limiting & billing                              │
└───────────────────┬─────────────────────────────────────┘
                    │
        ┌───────────┼───────────┐
        │           │           │
        ▼           ▼           ▼
┌──────────┐  ┌──────────┐  ┌──────────────┐
│  OpenAI  │  │ Anthropic│  │  hanzo-node  │
│    API   │  │    API   │  │  (local AI)  │
└──────────┘  └──────────┘  └──────┬───────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
            ┌──────────────┐ ┌───────────┐ ┌────────────┐
            │ hanzo-engine │ │ casibase  │ │  hanzo-kbs │
            │ (inference)  │ │ (vectors) │ │    (RAG)   │
            └──────────────┘ └───────────┘ └────────────┘

Identity & Auth:
┌──────────────┐      ┌──────────────┐
│  hanzo-id    │◄─────┤   casdoor    │
│  (DID mgmt)  │      │  (SSO/Auth)  │
└──────────────┘      └──────────────┘

Infrastructure:
┌──────────────────────────────────────┐
│          hanzo-cloud                 │
│  - Service orchestration             │
│  - Load balancing                    │
│  - Monitoring (casvisor)             │
└──────────────────────────────────────┘
```

## Data Flow

### 1. **Inference Request**
```
Client → hanzo-gateway → authenticate (hanzo-id/casdoor) 
       → route to provider → return response
```

### 2. **Local AI Request**
```
Client → hanzo-gateway → hanzo-node → hanzo-engine (inference)
                                    → casibase (vector search)
                                    → hanzo-kbs (RAG)
```

### 3. **Training/Embedding**
```
Client → hanzo-gateway → hanzo-node → hanzo-engine (embedding)
                                    → casibase (store vectors)
```

## Dependency Strategy

### Development Phase
All Hanzo projects use git dependencies:
```toml
[dependencies]
hanzo-did = { git = "https://github.com/hanzoai/rust-sdk", branch = "main" }
hanzo-mcp = { git = "https://github.com/hanzoai/rust-sdk", branch = "main" }
```

### Production Phase
Published to crates.io:
```toml
[dependencies]
hanzo-did = "0.1"
hanzo-mcp = "0.1"
```

## Build Strategy

### hanzo-gateway (Fast Build)
```dockerfile
# Downloads pre-built binaries from hanzoai/node releases
FROM debian:bookworm-slim
RUN curl -L https://github.com/hanzoai/node/releases/latest/download/hanzo-node-x86_64.zip
# Build time: ~30 seconds
```

### hanzo-node (Source Build)
```dockerfile
# Compiles from source
FROM rust:latest
RUN cargo build --release --bin hanzo_node
# Build time: ~45 minutes (but only once per release)
```

## Release Workflow

### 1. **rust-sdk** releases
```bash
# Update crate
cd ~/work/hanzo/rust-sdk
# Bump version
cargo publish -p hanzo-did
git tag hanzo-did-v0.1.0
git push --tags
```

### 2. **hanzo-node** releases
```bash
cd ~/work/shinkai/hanzo-node
git tag v1.2.0
git push origin v1.2.0
# Triggers CI:
# - Builds binaries (linux, mac, windows)
# - Uploads to GitHub releases
# - Builds Docker image → hanzoai/hanzo-node:v1.2.0
```

### 3. **hanzo-gateway** releases
```bash
cd ~/work/hanzo/gateway
# Update HANZO_NODE_VERSION in workflow
git tag v0.2.0
git push origin v0.2.0
# Triggers CI:
# - Downloads pre-built hanzo-node binary
# - Builds fast Docker image (<30s)
# - Pushes to hanzoai/gateway:v0.2.0
```

## SDK Feature Parity

### Python SDK Features (to replicate in Rust)

1. **Client Library** (`hanzo-client`)
   - Connection management
   - Request/response handling
   - Authentication
   - Retry logic

2. **AI Chain Infrastructure** (`hanzo-aci`)
   - On-chain model registry
   - Decentralized compute market
   - Proof of inference

3. **Agent Framework** (`hanzo-agents`)
   - Tool calling
   - Memory management
   - Planning & reasoning
   - Multi-agent orchestration

4. **Model Context Protocol** (`hanzo-mcp`)
   - Tool definitions
   - Context management
   - Provider integration

5. **Memory Systems** (`hanzo-memory`)
   - Short-term memory
   - Long-term memory (vector DB)
   - Semantic memory

6. **Networking** (`hanzo-network`)
   - P2P networking (libp2p)
   - Node discovery
   - NAT traversal
   - Relay support

7. **REPL** (`hanzo-repl`)
   - Interactive shell
   - Command completion
   - History

## OpenAI Compatibility

All hanzo services expose OpenAI-compatible endpoints:

```python
# Works with any OpenAI client
import openai

client = openai.OpenAI(
    base_url="https://gateway.hanzo.ai/v1",
    api_key="hanzo_..."
)

response = client.chat.completions.create(
    model="hanzo/alibaba-qwen3-32b",  # Routes to hanzo-node
    messages=[{"role": "user", "content": "Hello!"}]
)
```

Supports routing to:
- OpenAI API
- Anthropic API
- Together AI
- Groq
- Local hanzo-node
- Any custom OpenAI-compatible endpoint

## Identity Integration

All requests authenticated via DID:
```
did:hanzo:gateway → did:hanzo:user123 → did:hanzo:node456
```

Features:
- Decentralized identity
- Key rotation
- Multi-device support
- OAuth 2.0 bridges (via casdoor)

## Next Steps

### Immediate (This Week)
1. ✅ Fix gateway Docker build (use pre-built binaries)
2. ✅ Update identity to did:hanzo:gateway
3. [ ] Create hanzo-node v1.2.0 release
4. [ ] Move core crates to rust-sdk
5. [ ] Update documentation

### Short Term (Next 2 Weeks)
1. [ ] Consolidate all shared crates in rust-sdk
2. [ ] Implement full client library in Rust
3. [ ] Publish initial crates to crates.io
4. [ ] Add comprehensive tests
5. [ ] Create examples & tutorials

### Long Term (Next Month)
1. [ ] Feature parity with python-sdk
2. [ ] Stabilize APIs for 1.0 release
3. [ ] Performance benchmarks
4. [ ] Production deployment
5. [ ] Developer documentation site

## Success Metrics

- [ ] Gateway build time < 1 minute
- [ ] Zero code duplication across repos
- [ ] All shared crates in rust-sdk
- [ ] Published to crates.io & docs.rs
- [ ] OpenAI compatibility test suite passing
- [ ] End-to-end integration tests
- [ ] Production-ready documentation
