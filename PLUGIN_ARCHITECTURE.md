# Gateway Plugin Architecture

## Overview

Gateway loads backend services as in-process Go plugins instead of reverse-proxying to separate containers.

```
gateway --plugins=ats,bd,ta,kms serve
```

Single binary serves: API gateway + ATS + BD + TA + KMS. Each plugin gets its own SQLite DB.

## Interface

```go
type BackendPlugin interface {
    Name() string
    PathPrefix() string                    // e.g., "/v1/ats"
    Init(cfg PluginConfig) error           // bootstrap DB, migrations, hooks
    Handler() (http.Handler, error)        // return route handler
    Shutdown(ctx context.Context) error
}
```

## How It Works

1. Base-powered services (ATS/BD/TA/KMS) expose `NewPlugin()` → `BackendPlugin`
2. Plugin `Init()` calls `core.NewBaseApp()` + `app.Bootstrap()` (no HTTP server)
3. Plugin `Handler()` calls `apis.NewRouter(app)` → `router.BuildMux()` → `http.Handler`
4. Gateway mounts via `gin.WrapH(http.StripPrefix(prefix, handler))`
5. Auth: gateway middleware validates JWT first, plugins trust `X-User-Id` headers

## Build

```bash
# Plugin mode (single binary)
go build -tags "plugin_ats,plugin_bd,plugin_ta,plugin_kms" ./cmd/gateway

# Standalone mode (separate containers, unchanged)
cd ~/work/liquidity/ats && go build .
```

## Config

```
GATEWAY_PLUGINS=ats,bd,ta,kms
GATEWAY_PLUGIN_DATA_DIR=/data
IAM_ENDPOINT=https://iam.dev.
```

## Implementation Order

1. `BackendPlugin` interface in gateway
2. Refactor ATS → `plugin.go` with `NewPlugin()`
3. `PluginManager` in gateway
4. Mount in `router_engine.go` via `gin.WrapH()`
5. BD, TA, KMS (same pattern)
6. IAM (Beego — keep as reverse proxy initially)

## Container Reduction

```
Before: gateway + iam + ats + bd + ta + kms = 6 containers
After:  gateway (with plugins) + iam = 2 containers
Local:  gateway --plugins=iam,ats,bd,ta,kms = 1 container
```
