# gateway — memory profile

Procedure for verifying the gateway meets its memory budget:

| State | Target |
|---|---|
| Idle (no connections) | < 64 MiB RSS |
| 10,000 in-flight connections | < 200 MiB RSS |

## Why these numbers

KrakenD + gin is the heaviest piece in the gateway today. fasthttp-flavored frameworks usually idle around 8-16 MiB; KrakenD with the proxy chain, JWKS cache, plugin registry, and route table sits in the 30-50 MiB range cold. At 10k in-flight TCP conns, expect ~10k goroutines × 8 KiB initial stack + a per-conn read/write buffer pair (~16 KiB), call it ~240 MiB worst case before pooling. Pooling on the fasthttp side brings this down. The 200 MiB target is what's left after sensible buffer reuse — anything above means a leak or unbounded per-conn allocation.

## Harness

Build the gateway with pprof enabled (pprof is wired in via KrakenD's
`telemetry/metrics` config but a standalone endpoint is the cleanest
measurement surface). Add this snippet to `cmd/gateway/main.go` behind
an env flag if not already there:

```go
if os.Getenv("GATEWAY_PPROF") != "" {
    go func() {
        if err := http.ListenAndServe("localhost:6060", nil); err != nil {
            log.Println("pprof:", err)
        }
    }()
}
```

(The `net/http/pprof` package auto-registers handlers via `init()`; the
import is enough.)

Build:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags='-s -w' -o ./bin/gateway ./cmd/gateway
```

Run:

```sh
GATEWAY_PPROF=1 ./bin/gateway run -c configs/hanzo/gateway.json
```

## Idle measurement

After the gateway is up and serving 0 requests:

```sh
curl -o idle.pprof -s http://localhost:6060/debug/pprof/heap
go tool pprof -top -unit=mb idle.pprof | head -20
```

Record the `flat` total in MiB. The target is `< 64`.

## 10k-in-flight measurement

Use `loadgen/conn_holder/main.go` (committed alongside this doc) to open
10,000 idle keep-alive HTTP/1.1 connections and hold them:

```sh
go run ./loadgen/conn_holder \
  -target=http://localhost:8080/healthz \
  -conns=10000 \
  -hold=120s
```

While the holder is running, capture the heap profile and the RSS:

```sh
curl -o conn10k.pprof -s http://localhost:6060/debug/pprof/heap
ps -o rss= -p "$(pgrep -f bin/gateway)"
```

RSS is the system view (page table); `pprof` shows the Go heap. Target:
RSS < 200 MiB. The two numbers diverge when sysmap is large (mmap'd
stacks, GC arenas); track both.

## When to re-measure

- After every dep bump that touches `fasthttp`, `gin`, `KrakenD/lura`,
  or `krakend-koanf` (the heavy bottom-of-stack libs).
- After every change to `auth_middleware.go` that adds new per-request
  allocations (e.g. new claim extraction, new headers minted).
- After every change to `zap_backend.go` or `base_ha_backend.go`
  affecting backend transport pooling.

## Current measurement (2026-05-19)

**UNMEASURED.** Build is broken on `feat/edge-scale-cleanup` ←→ `main`:

```
go: inconsistent vendoring in /Users/z/work/hanzo/gateway:
    github.com/hanzoai/cloud@v0.0.0: is marked as replaced in vendor/modules.txt, but not replaced in go.mod
    github.com/hanzoai/zip@v0.0.0: is marked as replaced in vendor/modules.txt, but not replaced in go.mod
```

Cause: commit `56397a4` ("fix(ci): drop ../cloud + ../zip replace
directives, use pseudo-versions") removed the replace directives in
go.mod but `vendor/modules.txt` still references them. Either:

1. `go mod vendor` to refresh, and pseudo-versions of `cloud` and
   `zip` must exist on a reachable VCS path (currently `v0.0.0` —
   doesn't exist). OR
2. Re-add the replace directives in go.mod for local sibling-repo
   development; drop only for CI.

This is in the parallel agent's scope (`feat/hip-0110-gateway-edge-process`).
Re-measure once the build is restored.
