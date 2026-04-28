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
(any of: numeric bit-field, `[]string` of names, `[]{"name":"..."}` Casdoor
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
