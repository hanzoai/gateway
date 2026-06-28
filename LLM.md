# LLM.md - Hanzo Gateway

## Overview
Go module: github.com/hanzoai/gateway

## Tech Stack
- **Language**: Go

## Build & Run
```bash
go build ./...
go test ./...
```

## Structure
```
gateway/
  Dockerfile
  LICENSE
  LLM.md
  Makefile
  README.md
  SECURITY.md
  auth_middleware.go
  auth_middleware_test.go
  backend_factory.go
  builder/
  cmd/
  configs/
  deps.sh
  encoding.go
  executor.go
```

## Key Files
- `README.md` -- Project documentation
- `go.mod` -- Go module definition
- `Makefile` -- Build automation
- `Dockerfile` -- Container build

## JWT Audience Allowlist (edge auth)

`iamauth.ValidateToken` validates `iss` (strict, env `AUTH_ISSUER`, prod
`https://iam.hanzo.ai`) and `aud` against an **allowlist** (OR semantics — a
token passes if its `aud` matches ANY entry). IAM (Casdoor) stamps user tokens
with `aud = <client_id>` (the seeded app name: `hanzo-app`, `hanzo-console`,
`hanzo-chat`, `hanzo-id`, …), never the gateway origin — so the prior single
fixed audience (`https://api.hanzo.ai`) rejected EVERY normal user JWT (cowork
AI 401, user billing 401).

- Single source of truth: `iamauth.DefaultAudiences` (the known user-facing
  client_ids + `https://api.hanzo.ai`) and `iamauth.AudiencesFromEnv()`. Shared
  by the gin/KrakenD middleware (`auth_middleware.go`), the relay gate
  (`gate.go`), the unified-binary mount (`mount.go`), and the ingress
  (`cmd/ingress`). One implementation, four callers.
- Override entirely with `GATEWAY_ALLOWED_AUDIENCES` (comma-separated). Legacy
  `AUTH_AUDIENCE` / `JWT_AUDIENCE`, when set, are folded IN (widen, never
  narrow — a live env pinned to `AUTH_AUDIENCE=https://api.hanzo.ai` keeps that
  value in an already-inclusive set rather than collapsing to one entry).
- The allowlist is never empty by construction, so the audience check is
  ALWAYS enforced. `aud` outside the set fails; a missing/empty `iss` fails.
- Forwards-only: append new client_ids to `DefaultAudiences`, never remove.
- Regression: `iamauth/audience_test.go` (aud=hanzo-app/hanzo-chat PASS,
  aud=evil FAIL, wrong issuer FAIL) + `TestJWTAuth_RejectsWrongAudience`.

## Identity Headers (Trust Boundary)

Gateway is the **only** authority that may emit identity headers downstream.
On every request the middleware unconditionally `Header.Del`s every header it
mints (see `stripIdentityHeaders` in `auth_middleware.go`) BEFORE any bypass
path runs (public hosts, public paths, API keys, no-token pass-through). After
JWT validation, the gateway re-injects the headers from the validated claims.

| Header              | Source claim         | Type                                  |
|---------------------|----------------------|---------------------------------------|
| X-User-Id           | `sub`                | string                                |
| X-Org-Id            | `owner`              | string (org slug)                     |
| X-Roles             | `roles`              | comma-joined role names               |
| X-User-Email        | `email`              | string                                |
| X-Phone-Number      | `phone_number`/`phone` | E.164 string                        |
| X-User-IsAdmin      | `isAdmin`            | "true" iff platform superadmin        |
| X-User-Permissions  | `permissions`+`isAdmin` | base-10 int64 bit.Field            |

**X-User-Permissions** is gateway-derived from the JWT `permissions` claim
(any of: numeric bit-field, `[]string` of names, `[]{"name":"..."}` upstream-IAM
permission objects). Names are looked up in `permissionBits` (see
`auth_middleware.go`); unknown names are dropped silently (forwards-compatible
with new IAM permissions). If the JWT carries `isAdmin: true` the gateway also
ORs in `permission.Admin | permission.Live` (16 | 4 = 20). The header is
omitted when the resulting bit-field is zero — commerce treats absent and "0"
identically (`bit.Field(0)`, fail-closed, see `commerce/middleware/iammiddleware`).

The single source of truth for bit positions is
`commerce/util/permission/permission.go` — `permissionBits` here mirrors the
iota order there. Forwards-only: never re-number, only append.

**Strip-list ⊇ mint-list contract**: every header in
`gatewayMintedIdentityHeaders` MUST be stripped on ingress. The contract is
enforced by `TestStripList_CoversAllMintedHeaders` and
`TestStripIdentityHeaders_AllVariants` — these MUST pass before merge.

Red P0-1 closed (2026-04-27): prior to this fix, the gateway neither stripped
nor minted `X-User-Permissions`, allowing `curl -H "X-User-Permissions: 16"`
to grant Admin in commerce. See `auth_middleware_security_test.go` Test 21.

## Edge Route Auth Classes + Billing (must-gate hardening, 2026-06-27)

`configs/hanzo/gateway.json` endpoints fall in three auth classes:

- **PUBLIC** (13): health/discovery/catalog (`/`, `/health`, `/v1/*/health`,
  `/v1/get-providers`, `/v1/get-provider`, `/v1/pricing-policy`, `/v1/models`,
  `/v1/analytics/heartbeat`, `/v1/pubsub/healthz`, `/bot/health`). No
  `auth/validator`. `/v1/get-providers` / `/v1/get-provider` self-protect at the
  backend (session auth); `/v1/get-global-providers` does NOT and is must-gate.
- **AI / API-KEY** (8): `/v1/chat`, `/v1/chat/completions`, `/v1/completions`,
  `/v1/messages`, `/ai/{path}`, `/v1/ai/{path}`. NO IAM-JWT validator — these
  use opaque API keys (hk-/sk-) and are billed per-token by cloud-api. Adding
  an `auth/validator` here would 401 every API-key call.
- **MUST-GATE** (25, IAM-JWT): `/cloud/{path}`, `/v1/cloud/{path}`,
  `/v1/commerce/{path}`, `/v1/tasks/{path}`, `/v1/insights/{path}`,
  `/v1/o11y/{path}`, `/v1/mpc/{path}`, `/v1/evals/{path}`,
  `/v1/licensing/{path}`, `/v1/product/{path}`, `/v1/provisioning/{path}`,
  `/v1/ml/*`, `/v1/train/*`, `/v1/get-global-providers`, `/v1/add-provider`,
  `/v1/update-provider`. Each carries the canonical `auth/validator` block
  (RS256, `https://hanzo.id/.well-known/jwks`, `propagate_claims`
  sub→X-User-Id / owner→X-Org-Id / roles→X-Roles) and `input_headers` = the VH
  set. Result: **401 at the edge without a valid JWT**. Audience is NOT checked
  here — krakend-jose ALL-semantics would 401 every single-aud user token; it is
  enforced at the Go edge instead (see "Edge auth — landmines").

**GOTCHA — `hostProxyMiddleware` validator bypass**: for host `api.hanzo.ai`,
any path whose prefix is in `apiHanzoAIEndpoints` (`router_engine.go`:
`/v1/chat`, `/v1/completions`, `/v1/messages`, `/v1/models`, `/v1/embeddings`,
`/v1/images`, `/v1/audio`, `/v1/zap`, `/zap`) is reverse-proxied straight to
cloud-api and **the per-route `auth/validator` in gateway.json is never run**
(cloud-api enforces the API key instead). So those AI routes' config validator
is effectively inert. NEVER add a must-gate route under one of those prefixes —
its edge validator would be silently bypassed. Matching is segment-boundaried
(`matchesAPIEndpoint`: path `== prefix` or `prefix+"/"`), so `/v1/models` does
NOT also capture `/v1/modelsX` / `/v1/models-internal`.

**Billing — path-scoped balance gate** (`auth_middleware.go`): the global
`NewAuthMiddleware` enforces a commerce balance check ONLY when
`BILLING_ENABLED=true` AND the request path matches a `BILLING_PATHS` prefix.
This keeps billing OFF for the 171 AI/validated routes (AI bills per-token
downstream) and public routes, ON for the metered must-gate surface. Key is the
verified commerce `org/sub` user identity; per-org billing needs a commerce-side
balance-model change first. Fail-closed: 402 on zero balance, 503 if commerce
is unreachable. KrakenD cannot express this in `gateway.json` (no-op encoding
forbids a sequential balance pre-check), so it lives in the Go middleware.

Activation (NOT enabled by default — live is `BILLING_ENABLED=false`):
1. Provision `COMMERCE_SERVICE_TOKEN` from KMS (gateway-secrets).
   `AuthConfig.Validate()` makes it AND `AUTH_BILLING_URL` REQUIRED when
   `BILLING_ENABLED=true`: `gateway.Mount` refuses to start without them, and
   `NewAuthMiddleware` fails the metered surface closed (503) — never open.
   `mount.go` and `DefaultAuthConfig` read the SAME vars
   (`AUTH_BILLING_URL` / `COMMERCE_SERVICE_TOKEN`); no `BILLING_URL`/
   `BILLING_TOKEN` drift.
2. Set `BILLING_ENABLED=true` and
   `BILLING_PATHS=/v1/cloud/,/cloud/,/v1/tasks/,/v1/insights/,/v1/o11y/,/v1/mpc/,/v1/evals/,/v1/licensing/,/v1/product/,/v1/provisioning/,/v1/add-provider,/v1/update-provider`
   (`/v1/commerce` is hard-excluded in code — `billingPathMatch`, segment
   boundary — so it is NEVER balance-gated regardless of `BILLING_PATHS`; a 402
   on the funding surface would lock users out of adding funds).
3. Confirm commerce balance granularity before enabling.

Deploy = update ConfigMap `gateway-config` from this file + `rollout restart
deploy gateway`. NEVER `make apply-hanzo` (its manifest pins an older image tag
and downgrades the running gateway — live is ahead of the manifest).

## Edge auth — landmines

**Audience is enforced ONLY at the Go edge, NEVER in `gateway.json`.** The Go
`NewAuthMiddleware` validates `aud` against an ANY-of allowlist
(`iamauth.DefaultAudiences`, go-jose v4 `AnyAudience`): a token passes when its
single `aud=<client_id>` matches ANY entry. The KrakenD `auth/validator`
(krakend-jose → go-auth0 → go-jose **v3**) validates audience with
ALL-semantics — the token must carry EVERY configured `aud`. IAM stamps ONE
`aud` per token, so a multi-entry `"audience"` on any `gateway.json` validator
block 401s EVERY user JWT. `TestGatewayConfig_NoKrakendAudience` guards this —
keep `gateway.json` audience-free.

**`X-Project-Id` is stripped at the edge** (`iamauth.StripIdentityHeaders`): it
is forgeable and minted from no claim, so it can never reach a backend
(cross-project IDOR). Mint it here from a validated claim if/when IAM carries
one — same pattern as `X-Org-Id`.

**`/v1/get-global-providers` is must-gate.** It dumps the admin provider
inventory (names, base URLs, masked secrets) and the backend does NOT
self-protect it, so it carries the canonical `auth/validator` block. Its read
siblings `/v1/get-providers` / `/v1/get-provider` self-protect at the backend
("Please sign in first") via session auth and are intentionally left ungated —
a Bearer-only edge validator would break their cookie-auth callers.

## Upstream Kinds

- **default** — KrakenD HTTP passthrough.
- **zap** — binary RPC transport (`github.com/hanzoai/gateway/zap`).
- **base-network** — shard-aware routing over hanzoai/base network services (ATS, BD, TA, IAM, KMS, AML). `github.com/hanzoai/gateway/base-network`.
- **base_ha** — leader-pin routing over hanzoai/base-ha clusters (BaseApp CRD). `github.com/hanzoai/gateway/base_ha`. Polls `GET /_ha/leader` on the service DNS every `leader_poll_interval` (default 1s), pins write methods (POST/PUT/PATCH/DELETE or `X-Base-Writer: required`) to the elected writer pod, round-robins reads via the enclosing `host` (K8s ClusterIP). 5s read-your-writes pin per client (X-Forwarded-For + X-Org-Id) after a write. One-retry cap on writer 5xx/connect-refused (no retry storm on OOM). Stale-cache fail-secure: lease-expired + poll-stale → 503 instead of targeting a dead pod.

  Minimal per-backend config (add to an endpoint in `gateway.json`):
  ```json
  "backend": [{
    "url_pattern": "/v1/app/foo",
    "host": ["http://foo.hanzo.svc.cluster.local:8090"],
    "extra_config": {
      "github.com/hanzoai/gateway/base_ha": {
        "service_dns": "foo.hanzo.svc.cluster.local",
        "port": 8090,
        "leader_poll_interval": "1s",
        "read_your_writes_ttl": "5s"
      }
    }
  }]
  ```

  Prometheus metrics: `gateway_base_ha_leader_polls_total`, `gateway_base_ha_leader_poll_errors_total`, `gateway_base_ha_leader_changes_total`, `gateway_base_ha_writer_failures_total`, `gateway_base_ha_writer_failures_fatal_total`, `gateway_base_ha_no_writer_total`.
