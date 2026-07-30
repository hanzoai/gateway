# gateway middleware

Gateway-owned middleware for the zip web framework. Moved from
`github.com/hanzoai/zip/middleware/` because these concerns belong to
the gateway subsystem (not the generic web framework) per HIP-0106.

## Provided middleware

| Name | Purpose |
|---|---|
| `Auth(verifier AuthVerifier)` | Validate JWT, populate request context with claims, write X-Org-Id |
| `StripIdentityHeaders()` | Strip client-supplied X-Org-Id / X-User-Id / X-User-Email / X-User-IsAdmin / X-Roles / X-User-Permissions before validation |

## Pipeline order

```go
import (
    gw "github.com/hanzoai/gateway"
    "github.com/hanzoai/gateway/middleware"
)

app.Use(middleware.StripIdentityHeaders())  // first — strip client spoofing
app.Use(middleware.Auth(verifier))           // then — validate + write
// downstream handlers see gateway-written X-Org-Id
// and gw.AssertGatewayWritten(c) returns true
```

`AuthVerifier` is a one-method interface that adapts gateway's
auth-middleware to whatever JWT/JWKS implementation a deployment
provides (hanzoai/iam, gateway-sdk, a custom OIDC verifier).

## Trust assertion

After this middleware runs, downstream subsystems can verify the
request flowed through gateway via:

```go
import gw "github.com/hanzoai/gateway"

if !gw.AssertGatewayWritten(c) {
    return zip.Errorf(502, "expected gateway-written X-Org-Id")
}
```

This is defense in depth — it catches deployment misconfigurations
where a subsystem is accidentally exposed to direct (non-gateway)
traffic. Production cloud-mounted subsystems should reject the request
when the assertion fails; the failure is a deployment bug, not a
client problem.

## Why not in zip/middleware?

JWT validation + identity-header writing are the gateway subsystem's
responsibility per HIP-0106. Other subsystems mounted inside the
unified `cloud` binary trust the gateway-written `X-Org-Id` header and
do NOT re-validate JWTs themselves — re-running JWT validation
per-subsystem is wasteful and risks divergent validation rules.

Generic middleware (Recover, Logger, RequestID, Timeout, MaxBody,
CORS, RateLimit, Telemetry) stays in
[`github.com/hanzoai/zip/middleware`](https://github.com/hanzoai/zip/tree/main/middleware).
