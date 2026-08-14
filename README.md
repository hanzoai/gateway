<p align="center"><img src=".github/hero.svg" alt="gateway" width="880"></p>

# Hanzo Gateway

Gateway is the trust boundary in front of the Hanzo API. Every request to
`api.hanzo.ai` passes through it, and what it does is decide who the caller is
and whether the request may proceed — validate the JWT against Hanzo IAM's
JWKS, throw away every identity header the client sent, write the canonical
identity headers from the verified token, apply rate limits and circuit
breakers, emit telemetry, and hand the request on.

**It is not a router, and it deliberately does not have a route map.** For
`api.hanzo.ai` it forwards `/*` straight to [`hanzoai/cloud`](https://github.com/hanzoai/cloud)
with no per-route allow-list. Cloud's mount table is the one routing source of
truth; a second table here would be a second thing to get out of sync. The
comment above `apiCloudHosts` in [`routes.go`](routes.go) says it plainly, and
that is the rule to preserve when changing this repo.

The value of the boundary is exactly that downstream services never have to
wonder whether `X-Org-Id` came from a token or from a curl flag. It came from a
token, because gateway strips it unconditionally on the way in and rewrites it
on the way out.

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8.svg)](https://go.dev)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Where it sits

```
Internet
  -> Cloudflare
  -> hanzoai/ingress        TLS termination, L7, the front door
  -> hanzoai/gateway        identity, rate limit, circuit break, telemetry
  -> hanzoai/cloud          owns /v1/* routing (HIP-0106 mount table)
```

Ingress and gateway are different jobs and both are needed. Ingress terminates
TLS and decides which cluster service a hostname belongs to. Gateway decides
who the caller is. Neither does the other's work.

Implements HIP-0026 (the identity-header contract) and HIP-0106 (unified cloud
binary; gateway exposes `Mount()` so it can run in-process inside the cloud
binary instead of as a separate hop).

## Identity headers

Stripped from every inbound request, unconditionally, before anything else
reads them:

`X-User-Id`, `X-Org-Id`, `X-Roles`, `X-User-Email`, `X-Phone-Number`,
`X-User-IsAdmin`, `X-User-Role`, `X-User-Roles`, `X-User-Name`, `X-Tenant-Id`,
`X-Org`, and every `X-IAM-*` and `X-HANZO-*` variant.

Written from the validated JWT. These three are canonical:

| Header | Source claim |
|---|---|
| `X-User-Id` | `sub` |
| `X-Org-Id` | `owner` |
| `X-Roles` | `roles`, comma-joined |

Plus `X-User-Email` (`email`), `X-Phone-Number` (`phone_number` / `phone`) and
`X-User-IsAdmin` (`isAdmin`) when the token carries them.

`Authorization`, `Content-Type`, `Accept` and `X-Request-ID` pass through
untouched. Opaque API keys (`sk-`, `pk-`, `fw_`, `hz_`) are not JWTs and
are forwarded to the backend that owns them for validation.

## Calling the API

Get a key from [console.hanzo.ai](https://console.hanzo.ai) and send it as a
bearer token:

```bash
curl https://api.hanzo.ai/v1/chat/completions \
  -H "Authorization: Bearer $HANZO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"enso","messages":[{"role":"user","content":"Hello"}]}'
```

Model ids come from the catalog, not from this repo — gateway does not know
what a model is. `curl https://catalog.hanzo.ai/v1/models` lists them.

The API surface itself is documented at
[docs.hanzo.ai/docs](https://docs.hanzo.ai/docs); the route table lives in
`hanzoai/cloud`. This README deliberately does not reproduce either, because a
copy here would be the second source of truth the design exists to avoid.

## Rate limiting

Configured in `configs/<brand>/gateway.json` under
`qos/ratelimit/router`. Current Hanzo values:

| Scope | Limit |
|---|---|
| Global | 5,000 req/s |
| Per client IP | 100 req/s |

Individual endpoints can override this in their own `extra_config`. Rejected
requests get `429` with `Retry-After`.

## Health

| Path | What it answers |
|---|---|
| `/healthz` | The process is up |
| `/health` | Backends are reachable |

## Build and run

```bash
make build          # gateway binary (legacy HTTP edge, BUILD_TAGS=legacy)
make build-ingress  # ingress sidecar binary
make test           # both builds
make validate       # validate every config
```

Images are published per brand, not as a bare `latest`:

```bash
docker run -p 8080:8080 ghcr.io/hanzoai/gateway:hanzo-latest
```

`hanzo-latest` and `lux-latest` are the two brand tags, alongside
`<brand>-<sha>` for pinning. `make docker-hanzo` / `make docker-lux` build
them; `make deploy-hanzo` / `make deploy-lux` apply to the clusters.

### `GOEXPERIMENT=jsonv2`

The HIP-0106 in-process mount runs on `hanzoai/zip`, which routes JSON through
stdlib `encoding/json/v2` when the binary is built with the experiment on. The
Dockerfile and CI set it; manual builds should too:

```bash
GOEXPERIMENT=jsonv2 make build
```

Without it the binary still builds and runs — zip falls back to `encoding/json`
v1. v2 is preferred in production: roughly 10% faster and 25% fewer allocations
per request. The startup log line `json_variant=encoding/json/v2` confirms it is
active. No third-party JSON library is permitted in the Hanzo Go stack; stdlib
only.

## Configuration

```
configs/
  hanzo/gateway.json    Hanzo config
  hanzo/ingress.json    ingress sidecar config
  lux/                  same, Lux brand
k8s/                    cluster manifests
cmd/gateway/            gateway entry point
cmd/ingress/            ingress sidecar entry point
tests/                  integration tests
```

An endpoint entry declares the path, the input headers it is allowed to carry,
and the backend host — no path rewriting, since cloud speaks `/v1/*` natively:

```json
{
  "endpoint": "/v1/chat/completions",
  "method": "POST",
  "input_headers": ["Authorization", "Content-Type", "Accept", "X-Request-ID",
                    "X-Org-Id", "X-Project-Id", "X-Billing-Account-Id"],
  "output_encoding": "no-op",
  "backend": [{
    "url_pattern": "/v1/chat/completions",
    "host": ["http://cloud.hanzo.svc.cluster.local:8000"],
    "encoding": "no-op"
  }]
}
```

These per-endpoint entries drive the legacy HTTP edge build. The default build
is the passthrough relay described at the top: it does not consult them for
`api.hanzo.ai`.

Run `make validate` after any config edit.

## Related

| Repository | Role |
|---|---|
| [`hanzoai/ingress`](https://github.com/hanzoai/ingress) | The L7 front door — TLS, Kubernetes Ingress, load balancing |
| [`hanzoai/cloud`](https://github.com/hanzoai/cloud) | The API itself; owns the `/v1/*` mount table |
| [`hanzoai/iam`](https://github.com/hanzoai/iam) | Issues the tokens gateway validates |
| [`hanzoai/engine`](https://github.com/hanzoai/engine) | Serves models on cloud GPUs |
| [`hanzoai/edge`](https://github.com/hanzoai/edge) | On-device inference runtime — runs models locally, not part of this path |

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

The service-assembly layer derives from upstream Apache-2.0 projects and is
built on the [Lura](https://github.com/luraproject/lura) framework. The
authoritative attributions are preserved verbatim in [NOTICE](NOTICE).
