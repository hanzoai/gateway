# LLM.md - Hanzo Gateway

## Overview
Go module: github.com/hanzoai/gateway

## Tech Stack
- **Language**: Go

## Build & Run
```bash
go build ./...                    # default — Lura-free (NOT what ships)
go build -tags legacy ./...       # legacy  — full Lura engine; SHIPS
go test ./...                     # unit packages only
go test -tags legacy ./...        # + the tests/ integration harness
```

**The `legacy` build is what ships.** `Makefile` sets `BUILD_TAGS ?= legacy`
and the `Dockerfile` runs `make build` with no override, so
`ghcr.io/hanzoai/gateway` is the Lura engine, and `CMD ["run", "-c",
...]` is the legacy cobra subcommand that only exists under that tag. The
default build currently serves only `/healthz` and 404s model calls until the
HIP-0110 ZAP relay backends are live — see the rationale above `BUILD_TAGS` in
the Makefile. Upstream Lura security patches therefore still matter to
production; they are not quarantined away.

Local verification must mirror the Dockerfile (`CGO_ENABLED=0`) and bypass the
repo-adjacent `~/work/hanzo/go.work`, which does not list this module:

```bash
GOWORK=off CGO_ENABLED=0 go build ./... && GOWORK=off CGO_ENABLED=0 go build -tags legacy ./...
```

## Framework Ownership — Lura is `legacy`-gated (#29)

The gateway owns its module path (`github.com/hanzoai/gateway/v2`) and its
default build is **Lura-free**. The upstream Lura framework
(`github.com/luraproject/lura/v2` + `github.com/krakend/*`) is quarantined
behind the `legacy` build tag and never reaches `go build ./...`.

It DOES reach the shipping `ghcr.io/hanzoai/gateway` image, because that image
is built `-tags legacy` (`BUILD_TAGS ?= legacy`). The quarantine is a
source-layering boundary, not a production-exposure boundary — do not read it
as "the legacy engine is not in prod". Verify:

```
go list -deps ./cmd/gateway              | grep -c 'krakend\|lura'   # -> 0
go list -tags legacy -deps ./cmd/gateway | grep -c 'krakend\|lura'   # -> 105
```

| Build | Command | Lura pkgs | Contents | Ships? |
|-------|---------|-------------------|----------|--------|
| **default** | `go build ./...` | **0** | HIP-0110 ZAP relay + pure reverse-proxy router (`routes.go`, `mount.go`, `build_app.go`, `gate.go`, `auth_middleware.go`) | no — `/healthz` only until Phase C |
| **legacy** | `go build -tags legacy ./...` | 105 | full Lura gin engine (`legacy_engine.go` + factories) | **yes — this is the image** |

Ownership boundary:

| Dependency | Module path | Ownership | Reaches default build? |
|-----------|-------------|-----------|------------------------|
| gateway | `github.com/hanzoai/gateway/v2` | **fork — ours, own path** | yes (whole module) |
| Lura core | `github.com/luraproject/lura/v2` | upstream, pinned | **no** — `legacy`-only |
| krakend-* (24 pkgs) | `github.com/krakend/*` | upstream, pinned | **no** — `legacy`-only |
| ZAP edge | `github.com/zap-proto/http`, `github.com/luxfi/zap` | ours/fork | yes (default relay) |

`legacy`-gated files (every lura/krakend importer): `backend_factory`,
`base_ha_backend`, `base_network_backend`, `encoding`, `executor`,
`handler_factory`, `plugin`, `proxy_factory`, `rebrand`, `sd`, `zap_backend`,
`zaphttp_listener`, `legacy_engine` (+ their `_test.go`), the `tests/` Lura
integration harness, `cmd/gateway-integration`, and
`cmd/gateway/{main_legacy,rebrand}.go`. The default routing/auth/mount/ZAP-relay
surface already imports zero krakend/lura.

**Branding**: user-visible upstream-brand strings — HTTP (`X-KRAKEND`→`X-Powered-By`,
backend `User-Agent`→`hanzoai/gateway`) in `rebrand.go`, and the cobra CLI tree
in `cmd/gateway/rebrand.go` — are scrubbed only in the legacy engine. The
default build emits no upstream-brand strings because it contains none of that code.

**Phase-C end state**: when the cloud binary's `gateway.Mount` is the sole edge,
the entire `legacy` set is deleted and the upstream Lura dependency drops
out of `go.mod`. Until then it stays compilable under `-tags legacy` for rollout
safety. Forwards-only: never add a lura/krakend import to a non-`legacy` file.

## Upstream sync — krakend-ce v2.12.x → v2.13.8 (2026-07-25)

This fork has **no shared git history** with `krakend/krakend-ce` (it began as a
squashed import), so there is no merge-base and `git merge` is not available.
Syncing is a deliberate content-level port: diff our copies of the seven derived
service-assembly files against an upstream tag, take the delta, keep ours.

Base identified by content-diffing every upstream tag: our derived sources
matched **v2.12.x** (137 residual lines = our own deltas). Now at **v2.13.8**.

krakend-ce is a thin assembly repo — the v2.12.1→v2.13.8 source delta is only
`backend_factory.go` (17 lines), `executor.go` (3), `Makefile`, and
`tests/`. The substance of an upgrade is the **dependency graph**.

Taken:

| Change | Why |
|---|---|
| `krakend-xml` v2.2.0 → **v2.2.2** | **security** — exponential-cost XML rendering (algorithmic-complexity DoS); drops `clbanning/mxj` |
| `go-jose/v3` v3.0.4 → **v3.0.5** (transitive) | **security** — JOSE lib under `krakend-jose` |
| `krakend-jose` v2.10.0 → **v2.12.3** | JWT validation path |
| `lura` v2.12.1 → **v2.14.1** | core framework; **real tag**, not upstream's `v2.14.2-0.2026…` pseudo-version |
| `backend_factory.go` ctx propagation | **bug** — app context never reached client plugins, so they missed cancellation/shutdown (upstream `16a23d2`) |
| `krakend-circuitbreaker` v2 → **v3** | import path change; pulls `sony/gobreaker/v2` |
| `krakend-pubsub` v2.2.0 → **v2.3.1** + drop `pubsub.OpenCensusViews` | **forced**: `gocloud.dev` v0.45.0 removed that symbol, breaking pubsub v2.2.0 |
| `tests/integration.go` → `santhosh-tekuri/jsonschema/v6` | drops unmaintained `xeipuuv/gojsonschema` |
| `expected.Body != ""` → `!= nil` | **bug** — `Body` is `interface{}`, so a nil body compared true against `""` and wrongly asserted. Fixture `integration_no_body.json` added as the guard |
| botdetector, cel, cobra, cors, flexibleconfig, httpsecure, jsonschema, lua, martian, metrics, opencensus, ratelimit, go-auth0 | routine patch/minor bumps |

**Deliberately NOT taken** (re-adding any of these is a regression):

- `krakend-usage` — the upstream phone-home telemetry. `startReporter` is a no-op
  here on purpose. `krakend-audit` stays indirect (it exists only to feed it).
- `krakend-otel` + the jaeger / ocagent / stackdriver OpenCensus exporters —
  all ship telemetry over **gRPC**; Hanzo speaks ZAP/HTTP/WS, never gRPC.
- `go-contrib/uuid` — only used by the usage reporter.
- Upstream's `cors.NewRunServerWithLogger` wrapper — this fork serves its own
  CORS preflight via `hostProxyMiddleware`; taking it double-sets headers.
- `router_engine.go`, `krakend.json`, upstream `Makefile`/`README`/`SECURITY.md`
  branding — superseded by `legacy_engine.go` + `configs/{hanzo,lux}`.

**Load-bearing upstream literals — never rebrand these.** Everything else in
this repo is de-branded; these four are behaviour, not branding:

| Literal | Where | Why it is pinned |
|---|---|---|
| `core.KrakendVersion`, `core.KrakendUserAgent` | `rebrand.go`, Makefile ldflags | exported lura symbols; renaming breaks the build. `rebrand.go` overwrites their *values* with the Hanzo brand — that is the correct seam |
| `KRAKEND_` env prefix (e.g. `KRAKEND_PORT`) | `config_loader_test.go` | the koanf parser hardcodes the prefix as a const; not configurable |
| `X-KRAKEND`, `X-Krakend-Completed` | `rebrand.go`, `production_headers_test.go` | compile-time consts in `lura/core`. `rebrand.go` **deletes** them off every response and the tests assert they never leak — the literal exists here in order to be removed |
| `github.com/devopsfaith/krakend*` extra_config keys | the `aliases` map in `cmd/gateway/main_legacy.go` | these are the canonical namespaces each component registers under; `aliases` maps the friendly name (`auth/validator`) onto them via `config.ExtraConfigAlias`. Rename the canonical side and the component stops finding its config — silently. Note `configs/*/gateway.json` uses only the *friendly* names, so the configs themselves are already brand-free |

Two entries that used to be on this list are gone because they were not
actually pinned: the auth realm equivalent (`zaphttp_listener.go`'s listener
env var) is the fork's own knob read by direct `os.Getenv`, not koanf, so it
is now `GATEWAY_ZAP_LISTEN` in line with `GATEWAY_LISTEN` /
`GATEWAY_SHUTDOWN_TIMEOUT`; and the negative-assertion brand lists in
`brand_test.go` / `production_headers_test.go` keep the upstream token on
purpose — they are the regression guard that fails if the brand ever leaks
into a `Server` header.

### Module paths — conversion BLOCKED on missing fork repos

The standing rule is that a hanzoai fork declares its OWN module path and is
required directly, never via `replace`. The ingress fork now satisfies this
(`github.com/hanzoai/yaegi`, `github.com/hanzoai/grpc-web`). **The gateway
does not, and cannot yet**: the 33 `github.com/krakend/*` modules in `go.mod`
resolve to *upstream*, not to hanzoai forks, and the corresponding fork repos
**do not exist**. Only `hanzoai/krakend-otel` exists — and its `replace` was
dead (`go mod why` reports the main module does not need it), so it has been
deleted rather than repointed.

Converting requires, per module, in dependency order: fork the upstream repo
at the pinned version, rewrite its module path, fix its self-imports *and*
its cross-references to the other forks, tag a patch bump, then repoint
`go.mod` here. Until those repos exist the `github.com/krakend/*` import lines
and the `go.mod`/`go.sum` require lines stay — a partial conversion would not
build. The full list is the require block at the top of `go.mod`.

`github.com/vulcand/oxy/v2` **was** repointed: it used to `replace` to the
upstream edge-router fork and now resolves to `github.com/hanzoai/oxy/v2` at
the identical commit ingress pins.

Module path stays `github.com/hanzoai/gateway/v2` — already v2 from the
krakend-ce v2 lineage, predating the "stay v1.x" rule. Do not "fix" it; a path
change would break every consumer for zero gain.

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

`edge.Verifier.VerifyRaw` validates `iss` (strict, env `AUTH_ISSUER`, prod
`https://iam.hanzo.ai`) and `aud` against an **allowlist** (OR semantics — a
token passes if its `aud` matches ANY entry). IAM stamps user tokens
with `aud = <client_id>` (the seeded app name: `hanzo-app`, `hanzo-console`,
`hanzo-chat`, `hanzo-id`, …), never the gateway origin — so the prior single
fixed audience (`https://api.hanzo.ai`) rejected EVERY normal user JWT (cowork
AI 401, user billing 401).

- Single source of truth: hanzoai/authz/edge.DefaultAudiences` (the known user-facing
  client_ids + `https://api.hanzo.ai`) and `token.AudiencesFromEnv()`. Shared
  by the gin/Lura middleware (`auth_middleware.go`), the relay gate
  (`gate.go`), the unified-binary mount (`mount.go`), and the ingress
  (`cmd/ingress`). One implementation, four callers.
- Override entirely with `GATEWAY_ALLOWED_AUDIENCES` (comma-separated). Legacy
  `AUTH_AUDIENCE` / `JWT_AUDIENCE`, when set, are folded IN (widen, never
  narrow — a live env pinned to `AUTH_AUDIENCE=https://api.hanzo.ai` keeps that
  value in an already-inclusive set rather than collapsing to one entry).
- The allowlist is never empty by construction, so the audience check is
  ALWAYS enforced. `aud` outside the set fails; a missing/empty `iss` fails.
- Forwards-only: append new client_ids to `DefaultAudiences`, never remove.
- Regression: `token/token.go` (aud=hanzo-app/hanzo-chat PASS,
  aud=evil FAIL, wrong issuer FAIL) + `TestJWTAuth_RejectsWrongAudience`.

## Identity Headers (Trust Boundary)

Gateway is the **only** authority that may emit identity headers downstream.
On every request the middleware unconditionally `Header.Del`s every header it
writes (see `stripIdentityHeaders` in `auth_middleware.go`) BEFORE any bypass
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

**Strip-list ⊇ write-list contract**: every header in
`authz.Headers` MUST be stripped on ingress. The contract is
enforced by `TestStripList_CoversAllWrittenHeaders` and
`TestStripIdentityHeaders_AllVariants` — these MUST pass before merge.

Red P0-1 closed (2026-04-27): prior to this fix, the gateway neither stripped
nor wrote `X-User-Permissions`, allowing `curl -H "X-User-Permissions: 16"`
to grant Admin in commerce. See `auth_middleware_security_test.go` Test 21.

## Edge Route Auth Classes + Billing (must-gate hardening, 2026-06-27)

`configs/hanzo/gateway.json` endpoints fall in three auth classes:

- **PUBLIC** (13): health/discovery/catalog (`/`, `/health`, `/v1/*/health`,
  `GET /v1/ai/providers`, `GET /v1/ai/providers/{owner}/{name}`,
  `/v1/pricing-policy`, `/v1/models`, `/v1/analytics/heartbeat`,
  `/v1/pubsub/healthz`, `/bot/health`). No `auth/validator`. The two provider
  reads self-protect at the backend (session auth); `GET
  /v1/ai/providers/global` does NOT and is must-gate.
- **AI / API-KEY** (8): `/v1/chat`, `/v1/chat/completions`, `/v1/completions`,
  `/v1/messages`, `/ai/{path}`, `/v1/ai/{path}`. NO IAM-JWT validator — these
  use opaque API keys (hk-/sk-) and are billed per-token by cloud. Adding
  an `auth/validator` here would 401 every API-key call.
- **MUST-GATE** (29, IAM-JWT): `/cloud/{path}`, `/v1/cloud/{path}` (both
  GET/POST/PATCH/DELETE), `/v1/commerce/{path}`, `/v1/tasks/{path}`,
  `/v1/insights/{path}`, `/v1/o11y/{path}`, `/v1/mpc/{path}`,
  `/v1/evals/{path}`, `/v1/licensing/{path}`, `/v1/product/{path}`,
  `/v1/provisioning/{path}`, `/v1/ml/*`, `/v1/train/*`,
  `GET /v1/ai/providers/global`, `POST /v1/ai/providers`,
  `PATCH /v1/ai/providers/{owner}/{name}`. Each carries the canonical `auth/validator` block
  (RS256, `https://hanzo.id/v1/iam/.well-known/jwks`, `propagate_claims`
  sub→X-User-Id / owner→X-Org-Id / roles→X-Roles) and `input_headers` = the VH
  set. Result: **401 at the edge without a valid JWT**. Audience is NOT checked
  here — krakend-jose ALL-semantics would 401 every single-aud user token; it is
  enforced at the Go edge instead (see "Edge auth — landmines").

**GOTCHA — `hostProxyMiddleware` validator bypass**: for host `api.hanzo.ai`,
any path whose prefix is in `apiHanzoAIEndpoints` (`routes.go`:
`/v1/chat`, `/v1/completions`, `/v1/messages`, `/v1/models`, `/v1/embeddings`,
`/v1/images`, `/v1/audio`, `/v1/zap`, `/zap`) is reverse-proxied straight to
cloud and **the per-route `auth/validator` in gateway.json is never run**
(cloud enforces the API key instead). So those AI routes' config validator
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
is unreachable. The config schema cannot express this in `gateway.json` (no-op encoding
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
   `BILLING_PATHS=/v1/cloud/,/cloud/,/v1/tasks/,/v1/insights/,/v1/o11y/,/v1/mpc/,/v1/evals/,/v1/licensing/,/v1/product/,/v1/provisioning/,/v1/ai/providers`
   (`/v1/commerce` is hard-excluded in code — `billingPathMatch`, segment
   boundary — so it is NEVER balance-gated regardless of `BILLING_PATHS`; a 402
   on the funding surface would lock users out of adding funds).
   `billingPathMatch` keys on PATH ONLY, so `/v1/ai/providers` meters the
   ungated GET reads too — the provider mutations are now distinguished by
   METHOD (POST/PATCH), which the prefix list cannot express. Drop the entry if
   read-metering is unacceptable.
3. Confirm commerce balance granularity before enabling.

Deploy = update ConfigMap `gateway-config` from this file + `rollout restart
deploy gateway`. NEVER `make apply-hanzo` (its manifest pins an older image tag
and downgrades the running gateway — live is ahead of the manifest).

## Edge auth — landmines

**Audience is enforced ONLY at the Go edge, NEVER in `gateway.json`.** The Go
`NewAuthMiddleware` validates `aud` against an ANY-of allowlist
(hanzoai/authz/edge.DefaultAudiences`, go-jose v4 `AnyAudience`): a token passes when its
single `aud=<client_id>` matches ANY entry. The config-declared `auth/validator`
(krakend-jose → go-auth0 → go-jose **v3**) validates audience with
ALL-semantics — the token must carry EVERY configured `aud`. IAM stamps ONE
`aud` per token, so a multi-entry `"audience"` on any `gateway.json` validator
block 401s EVERY user JWT. `TestGatewayConfig_NoJWTAudience` guards this —
keep `gateway.json` audience-free.

**`X-Project-Id` is stripped at the edge** (`edge.Strip`): it
is forgeable and written from no claim, so it can never reach a backend
(cross-project IDOR). Write it here from a validated claim if/when IAM carries
one — same pattern as `X-Org-Id`.

**`GET /v1/ai/providers/global` is must-gate.** It dumps the admin provider
inventory (names, base URLs, masked secrets) and the backend does NOT
self-protect it, so it carries the canonical `auth/validator` block. Its read
siblings `GET /v1/ai/providers` / `GET /v1/ai/providers/{owner}/{name}`
self-protect at the backend ("Please sign in first") via session auth and are
intentionally left ungated — a Bearer-only edge validator would break their
cookie-auth callers. `/v1/ai/providers/global` is 4 segments and the member
route is 5, so the ungated param route can never shadow it.

## Upstream Kinds

- **default** — legacy HTTP passthrough.
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
in order, all reusing hanzoai/authz/edge:
  1. the guard's own signed session cookie (HMAC, parent-domain `.hanzo.ai`, so
     one admin login covers every guarded `*.hanzo.ai` host) — browser fast path;
  2. a Bearer/Basic JWT via hanzoai/authz/edge.Validator.Validate` (the JWT already carries
     `owner`, no IAM round-trip) — API path;
  3. an IAM session cookie, resolved by calling IAM `GET /v1/iam/get-account`
     server-side and reading `owner` — browser-with-IAM-session path.

Login is standard OAuth2 PKCE against IAM (`client_id=hanzo-admin-guard`, app is
org-locked to `admin`). `Validator.ValidateRaw` (added to hanzoai/authz/edge) validates
the id_token/access_token from the code exchange.

Config (env): `IAM_PUBLIC_URL` (browser IAM), `IAM_INTERNAL_URL` (in-cluster IAM
for get-account/token), `IAM_CLIENT_ID`/`IAM_CLIENT_SECRET`, `IAM_ADMIN_ORG`,
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
expiry). Build via arcd BuildKit Job (Dockerfile `cmd/admin-guard/Dockerfile`),
NOT GHA.

## waitlist-guard — approval forward-auth gate (cmd/waitlist-guard)

Same forward-auth mechanism as admin-guard but the OPPOSITE surface: it fronts
the CONSUMER product hosts (console/billing/app/chat/team + gate api.hanzo.ai)
and lets through only APPROVED identities (IAM `User.IsApproved`: fail-open on an
absent `approvalStatus` property, gated only on an explicit `"pending"`; admins
always approved). Verdicts: 204 allow · 302→`WAITLIST_URL` (unapproved browser) ·
403 (unapproved API) · 302→IAM PKCE login (anonymous browser). Image
`ghcr.io/hanzoai/waitlist-guard`. Approval is stamped at signup in
`iam object.AddUser` (EVERY route: password/SSO/social/web3/email-code), so the
gate is not bypassable via a non-password signup.

Hardening vs the admin-guard clone (Red rework):
- **NO org pin.** `startLogin` must NOT set `organization=admin` (admin-guard
  does — it needs the admin identity). Consumer users log in under their own org;
  pinning admin would break their login. Global admins still resolve `owner==admin`.
- **Fail-OPEN on IAM 5xx** (`GUARD_FAIL_OPEN_ON_IAM_ERROR`, default true). `iamGet`
  is tri-state — `iamOK` / `iamUnavailable` (transport err or 5xx) / `iamDenied`
  (4xx). An authenticated caller (valid JWT or IAM session) whose approval lookup
  hits `iamUnavailable` is let THROUGH so an IAM blip never blackholes the money
  path; a 4xx never fails open; anonymous never fails open. The durable fast path
  is the HMAC-signed guard cookie (8h) — it short-circuits IAM entirely.
- **Inbound identity strip.** `handleVerify` runs `edge.Strip`
  (+ `stripWaitlistHeaders`) up front so a forged `X-Org-Id`/`X-Waitlist-*` can't
  be read by the guard. The AUTHORITATIVE upstream strip is the ingress headers
  middleware (must strip these before forwardAuth; the guard rewrites `X-Org-Id`
  via authResponseHeaders on allow).
- **Forwarded-Host allowlist.** `safeHost`/`hostAllowed` honor `X-Forwarded-Host`
  only for the cookie-domain suffix (or explicit `GUARD_ALLOWED_HOSTS`), else fall
  back to `r.Host` — a spoofed forwarded host can't steer `redirect_uri`/`returnTo`.

Config adds over admin-guard: `WAITLIST_URL`, `GUARD_FAIL_OPEN_ON_IAM_ERROR`,
`GUARD_ALLOWED_HOSTS`, `IAM_CLIENT_ID=hanzo-waitlist-guard`. Secrets:
`waitlist-guard-secrets` (GUARD_HMAC_KEY + IAM_CLIENT_SECRET). NetworkPolicy must
pin the gated services (paas:3000 etc) to ingress-only so the guard can't be
bypassed by hitting a Service ClusterIP directly. Tests:
`cmd/waitlist-guard/main_test.go` (fail-open tri-state, inbound strip, host
allowlist, no-org-pin, session forgery, approval predicate). Build via arcd
BuildKit Job (`cmd/waitlist-guard/Dockerfile`), NOT GHA. **Not wired to prod** —
cutover is a supervised one-host canary (see universe waitlist-guard docs).

## Test workflow green (fix/gateway-test-ci)

`.github/workflows/test.yml` was red on every commit while `Build and Deploy`
stayed green, because the test jobs ran go tooling directly on the
`hanzo-build-linux-amd64` runner without the environment the Dockerfile builder
provides. Root causes and fixes:

- Module auth: `go vet`/`go test` fell through to `direct` for private
  first-party modules (`hanzoai/cloud`, `zap-proto/*`) and died on
  `git ls-remote ... exit 128` — no git credential. Fixed by mirroring the
  Dockerfile module env (`GOPRIVATE=zap-proto/*`, `GONOSUMDB=zap-proto/*`,
  `GOSUMDB=off`, `GOPROXY=proxy,direct`, `GOFLAGS=-mod=mod`) plus a per-job
  `git config --global url."https://x-access-token:${GH_PAT}@github.com/".insteadOf`
  step — same GH_PAT the deploy Dockerfile secret uses, same pattern as
  `hanzoai/ingress` CI.
- `make: command not found` (127): the runner ships go (setup-go) but not
  make/wget. `make build` is replaced with a direct `go build -tags legacy`,
  reading `VERSION` from the Makefile and stamping `lura/v2/core.KrakendVersion`
  (the User-Agent the integration fixtures assert). The schema wget is dropped —
  `gateway check` runs fine with the empty embedded schema (`main_legacy.go`
  already falls back when `schema/schema.json` is absent).

Two tests were compile-/assert-broken and had been masked because go-tests
never ran (it `needs: go-vet`, which died at module fetch):

- `zaphttp_listener_test.go` called the removed net/http `Transport.RoundTrip`;
  `zap-proto/http@v0.1.0` is now a fasthttp-style client. Round-trip rewritten to
  `Transport.Do(*fasthttp.Request, *fasthttp.Response)`. fasthttp promoted to a
  direct require in go.mod (it already backed `fasthttpadaptor` in
  `zaphttp_listener.go`); go.sum untouched.
- `config_loader_test.go` asserted a `GATEWAY_PORT` koanf override, but upstream
  `krakend-koanf` hardcodes the `KRAKEND_` env prefix (a const, not
  configurable). Corrected to `KRAKEND_PORT`. The fork's own service knobs
  (`GATEWAY_LISTEN`, `GATEWAY_SHUTDOWN_TIMEOUT`) use GATEWAY_ via direct
  os.Getenv — a separate mechanism from koanf config-file key overrides.

Integration divergences (tracked, not fixed here): 12 of 59 lura fixtures in
`tests/` exercise upstream behaviour this edge fork diverges from and are
`-skip`'d in CI — `cors_1..5` (fork ships its own CORS preflight, not
`security/cors`), `backend_404`, `cel-1`, `cel-2`, `lua_2`, `router_redirect`,
`integration_jsonschema`, `negotitate_plain`. 47 integration cases + every unit
package gate CI. Re-enable per fixture as the edge binary grows the
matching component.

**The harness needs `-tags legacy` (fixed 2026-07-25).** Every file in `tests/`
is `//go:build legacy`, so the previous untagged `go test ./...` resolved
`./tests` to zero Go files and ran **no** integration fixture at all — the
`-skip` list was inert and the "46 cases gate CI" claim above was false for as
long as it stood. `test.yml` now runs two steps: unit packages
(`go list -tags legacy ./... | grep -v '/tests$'`) and the harness
(`./tests -args -gateway_startup_wait=30s`). They are separate because
`go test ./... -args` forwards the flag to every package's test binary and the
unit packages abort with `flag provided but not defined`.

`-gateway_startup_wait` matters: the harness `exec`s the ~190MB edge binary and
waits a **fixed** 1500ms before probing `:8080`. On a cold or loaded host that
is not enough and every fixture fails with `connection refused` — a startup
race, not a behavioural regression. Diagnose with
`go test -tags legacy ./tests -args -gateway_startup_wait=15s` before believing
a mass failure. The harness runs whatever binary is at `../gateway`, so
**rebuild it first** or you are testing a stale artifact:

```bash
VERSION=$(sed -n 's/^VERSION := *//p' Makefile)
CGO_ENABLED=0 go build -tags legacy \
  -ldflags="-X github.com/luraproject/lura/v2/core.KrakendVersion=${VERSION}" \
  -o gateway ./cmd/gateway
```
