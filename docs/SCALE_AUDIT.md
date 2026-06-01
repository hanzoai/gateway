# gateway — horizontal-scale audit

Branch: `feat/edge-scale-cleanup`. Coordinates with `feat/hip-0110-gateway-edge-process` (parallel agent, WIP — see "Blocker" below).

## Checklist

| Item | Status | Evidence / fix |
|---|---|---|
| No persistent state. Connection state only. | PASS | `auth_middleware.go` keeps a per-process JWKS cache (`newJWKSCache`, 5min TTL) and a per-process billing checker; both are recent-fetch memoizations, not authoritative state. No on-disk database; no session store. JWKS cache misses fall back to JWKS fetch — replicas converge independently. |
| No in-memory session cache (JWT is the session) | PASS | No session store. The JWKS cache holds *signing keys*, not user sessions — its eviction has no effect on which user is logged in. Verified by absence of any session/cookie storage primitive in `*.go`. |
| No per-replica DB connection | PASS | No `database/sql` import in the gateway repo. The billing checker is HTTP-only against commerce. ZAP is binary-RPC, also stateless on the gateway side. |
| Graceful shutdown drains in-flight requests | PASS | After HIP-0110 the canonical entrypoint is the zip-based `cmd/gateway/main.go`, which wraps the public + health listeners in `signal.NotifyContext(SIGINT, SIGTERM)` and drains them via `app.ShutdownWithContext(drainCtx)` under a deadline. The drain deadline is now operator-configurable via `GATEWAY_SHUTDOWN_TIMEOUT` (any `time.ParseDuration` string; defaults to 30s; falls back to the default on empty / malformed / non-positive values). Helper covered by `cmd/gateway/main_test.go::TestShutdownGraceFromEnv`. The legacy KrakenD path (`cmd/gateway/main_legacy.go`, `//go:build legacy`) remains untouched per the original audit note. |
| Routes config loadable from KMS (no plaintext routes secret on disk in prod) | PASS | `router_engine.go::loadRoutesFromEnv` now resolves `GATEWAY_ROUTES_KMS_PATH` through a `KMSResolver` interface defined in `router_kms.go`. Default resolver is a noop; the HTTP resolver activates automatically when `GATEWAY_KMS_ENDPOINT` + `IAM_CLIENT_ID/SECRET` (or the `GATEWAY_KMS_*` overrides) are set, speaking the same Universal-Auth + `/api/v3/secrets/raw/<path>` contract as `hanzoai/base/plugins/platform/kms.go`. File-based loader path (`GATEWAY_ROUTES_FILE` → `./routes.yaml`) is unchanged and remains the fallback. Covered by `router_engine_kms_test.go` (resolver injection, error surfacing, malformed-YAML guard, file fallback, HTTP round-trip stub). |
| All identity headers stripped from incoming external request before middleware runs | PASS | `stripIdentityHeaders` (auth_middleware.go:764) deletes X-User-Id, X-Org-Id, X-Roles, X-User-Permissions, X-User-Email, X-Phone-Number, X-User-IsAdmin, plus legacy X-User-Role, X-Tenant-Id/ID, X-Org, X-IAM-*, X-HANZO-* prefixes. Called unconditionally at the top of the middleware on EVERY path including bypass paths (auth_middleware.go:526, 545). Strip-list ⊇ mint-list contract enforced by `TestStripList_CoversAllMintedHeaders` and `TestStripIdentityHeaders_AllVariants`. |
| Auth middleware mints fresh identity headers from JWT and ONLY from JWT | PASS | After `stripIdentityHeaders`, only the JWT validation path (or the configured allowlists for opaque API keys like `hk-`, `sk-`, `fw_`, `hz_`) sets the headers. The X-User-Permissions bit-field derivation is documented in LLM.md and lives in one place (auth_middleware.go around line 797). |
| Forwards via ZAP to cloud. JSON only at client↔gateway boundary. | PASS | ZAP-HTTP backend transport (`zap_backend.go`) wraps `RoundTripper` and routes any backend whose `host:port` matches `INGRESS_ZAP_BACKENDS` over `github.com/zap-proto/http`. JSON sits at the client edge (KrakenD parses incoming JSON, encodes downstream); ZAP carries the inter-service hop. |
| Reverse-push channel from base via ZAP is wired | DEFER | Out of scope for this branch. The ZAP listener (`zap_listener.go`) exists for incoming binary calls. Reverse-push (base → gateway → client SSE) is the HIP-0110 deliverable; left to the parallel agent. |
| Memory < 64 MiB idle, < 200 MiB at 10k in-flight conns | UNVERIFIED → see docs/MEMORY_PROFILE.md | Gateway repo currently does not compile on this branch (vendor/go.mod mismatch from commit 56397a4 — replace directives dropped, vendor not refreshed). The audit ships the pprof harness + the procedure; the measurement runs after the build is unbroken. |
| No cgo. Static-linkable binary. | PASS | `grep -rn "^import \"C\"\|cgo" *.go cmd/` returns empty. Dockerfile builds `CGO_ENABLED=0`-able alpine binary. |
| One replica = same behavior as N replicas | PASS | Stateless apart from per-process JWKS + billing caches (each a memoization with TTL; cache misses converge). No leader election. No cross-replica coordination. ZAP RPC outbound is per-process. The breaker primitive (new in `hanzoai/zip/middleware/breaker.go`) is also per-process by design. |

## Memory profile

See `docs/MEMORY_PROFILE.md` for the harness. The harness is committed; the measured numbers update once the gateway build is restored.

## Blocker

`feat/hip-0110-gateway-edge-process` is the parallel agent's branch — it is restructuring the gateway from a KrakenD-resident process into a thin edge binary. Two changes intersect this audit:

1. `cmd/gateway/main.go` → `cmd/gateway/main_legacy.go` rename in the HIP-0110 branch.
2. New `middleware/auth.go` package with `gateway.SetGatewayMinted` / `gateway.AssertGatewayMinted` markers — these symbols are NOT yet defined in the gateway package, so the HIP-0110 branch does not build today.

Recommendation: let HIP-0110 land first. The breaker primitive in zip is the only piece of this audit's source-level scope that gateway will need to consume; it ships independently in `hanzoai/zip` and will be importable when HIP-0110 wires it into the gateway's ZAP client.

## Things deliberately NOT done in this branch

- The strip-list and mint-list audits — these are already covered by `auth_middleware_security_test.go::TestStripList_CoversAllMintedHeaders` and `::TestStripIdentityHeaders_AllVariants`. Re-asserting them here would be duplication, not coverage.
- Breaker integration in the ZAP client — gateway does not yet have an importable `hanzoai/zip` (build broken). Once HIP-0110 lands and the build is green, integration is a one-line wrap around the `*zaphttp.Transport` per-backend.
- Adding `GracefulShutdown` wrap around `cmd.Execute` — krakend-cobra ownership; touching it from this branch collides with HIP-0110 work.

## Update — post HIP-0110

- Graceful shutdown row moved PARTIAL → PASS now that the zip-based `cmd/gateway/main.go` owns lifecycle and `GATEWAY_SHUTDOWN_TIMEOUT` is configurable.
- KMS routes loader row added (PASS) — the `// TODO: KMS integration` in `router_engine.go::loadRoutesFromEnv` is replaced by the `KMSResolver` interface in `router_kms.go` with HTTP impl and stubbed tests. No behavior change when `GATEWAY_ROUTES_KMS_PATH` is unset.
