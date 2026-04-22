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
