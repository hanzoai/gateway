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
| X-User-IsAdmin      | `isAdmin`            | "true" iff ORG-level admin (org owner)|
| X-User-IsGlobalAdmin | `owner==AdminOrg` / `isGlobalAdmin` | "true" iff PLATFORM (global) admin |
| X-User-Permissions  | `permissions`+`isAdmin` | base-10 int64 bit.Field            |

**Org-admin vs global-admin (Red — anti-conflation):** `X-User-IsAdmin` is the
ORG-level admin role — an org owner (e.g. `maxpower`) carries `isAdmin=true`
within their own org. It is safe ONLY for org-scoped RBAC. The PLATFORM
superadmin signal is the SEPARATE `X-User-IsGlobalAdmin`, minted ONLY for a
caller who is `Claims.GlobalAdmin(AdminOrg)` — `owner == AdminOrg` (env
`IAM_ADMIN_ORG`, default `admin`) OR the explicit `isGlobalAdmin` claim.
Downstream services MUST gate cross-org / superadmin actions on
`X-User-IsGlobalAdmin` (commerce `auth.IAMClaims.GlobalAdmin()`), NEVER on
`isAdmin` — that conflation let any org owner perform tenant-admin ops. Both
headers are in the strip-list, so a client can forge neither. The org-level
`permission.Admin|Live` bit is still derived from `isAdmin` because it gates
org-SCOPED endpoints within the caller's namespace.

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

## admin-guard — global-admin forward-auth gate (cmd/admin-guard)

`cmd/admin-guard` is the single forward-auth gate that restricts Hanzo's RAW
global-admin surfaces to GLOBAL ADMINS ONLY. Image: `ghcr.io/hanzoai/admin-guard`.
Consumed by hanzoai/ingress (Traefik) as a `forwardAuth` Middleware whose
`address` is `http://admin-guard.hanzo.svc:8080/__guard/verify`.

Global admin = IAM user whose org (`owner`) equals the admin org (IAM
`IsGlobalAdmin`: `owner == conf.AdminOrg`, env `IAM_ADMIN_ORG`, default `admin`).

Endpoints:
- `GET /__guard/verify` — forward-auth target. 2xx = allow (global admin);
  302 = redirect (non-admin → `CONSOLE_URL`; anonymous browser → IAM PKCE login).
  API callers (Bearer/Basic, non-html Accept) fail closed with 401/403 instead
  of an interactive redirect.
- `GET /__guard/callback` — OAuth2 Authorization-Code + PKCE callback.
- `GET /__guard/logout`, `GET /__guard/healthz`.

Identity resolution — one predicate (`owner == AdminOrg`), three sources tried
in order, all reusing `iamauth`:
  1. the guard's own signed session cookie (HMAC, parent-domain `.hanzo.ai`, so
     one admin login covers every guarded `*.hanzo.ai` host) — browser fast path;
  2. a Bearer/Basic JWT via `iamauth.Validator.Validate` (the JWT already carries
     `owner`, no IAM round-trip) — API path. **Audience confinement (Red):** the
     JWT must carry `aud == adminAudience` (`GUARD_ADMIN_AUDIENCE`, default the
     guard's own `client_id`=`hanzo-admin-guard`). A genuine IAM token minted for
     ANOTHER app (e.g. `aud=hanzo-chat`), even a real global admin's, is rejected
     — API callers get **403** (`claims.HasAudience` gate, before the owner
     check); a browser falls through to interactive login. This stops a chat/app
     token from being replayed against raw admin surfaces.
  3. an IAM session cookie, resolved by calling IAM `GET /v1/iam/get-account`
     server-side and reading `owner` — browser-with-IAM-session path.

Login is standard OAuth2 PKCE against IAM (`client_id=hanzo-admin-guard`, app is
org-locked to `admin`). `Validator.ValidateRaw` (added to `iamauth`) validates
the id_token/access_token from the code exchange.

Config (env): `IAM_PUBLIC_URL` (browser IAM), `IAM_INTERNAL_URL` (in-cluster IAM
for get-account/token), `IAM_CLIENT_ID`/`IAM_CLIENT_SECRET`, `IAM_ADMIN_ORG`,
`GUARD_ADMIN_AUDIENCE` (the required token audience; default `IAM_CLIENT_ID`),
`AUTH_ISSUER`/`AUTH_JWKS_URL` + `GATEWAY_ALLOWED_AUDIENCES` (must include
`hanzo-admin-guard`), `CONSOLE_URL`, `GUARD_COOKIE_DOMAIN`/`_TTL`, `GUARD_HMAC_KEY`.

Deploy: operator `Service` CR `universe/infra/k8s/operator/crs/admin-guard-v1.yaml`
(internal-only, no ingress). Wiring: `universe/infra/k8s/ingress/routes.yaml`
middleware `admin-guard-auth` + per-host `/__guard` bypass routers (priority 200+)
+ `admin-guard-auth` attached to the gated routers (platform, app.platform,
studio, commerce-admin, kms `/admin`). The IAM management API self-gates
already (returns Unauthorized to non-admins) so iam.hanzo.ai/hanzo.id login &
oauth are left ungated. K8s secrets: `admin-guard-secrets`
(GUARD_HMAC_KEY + IAM_CLIENT_SECRET).

Tests: `cmd/admin-guard/main_test.go` (ownerFromAccount, HMAC sign/verify,
expiry) + `cmd/admin-guard/audience_guard_test.go` (audience confinement:
admin-aud+global→204, admin-aud+org-owner→403, wrong-aud+global→403,
wrong-aud+browser→login). Build via arcd BuildKit Job (Dockerfile `cmd/admin-guard/Dockerfile`),
NOT GHA.
