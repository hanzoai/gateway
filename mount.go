// Copyright © 2026 Hanzo AI. Apache-2.0 License.

// Package gateway exposes the HIP-0106 unified-binary mount surface for
// the Hanzo Gateway. In the unified cloud binary the gateway acts as
// the trust boundary: it validates JWTs, strips client-supplied
// identity headers, and writes the gateway-authorized X-Org-Id /
// X-User-Id / X-User-Email / X-Roles / X-User-Permissions /
// X-User-IsAdmin / X-Phone-Number set documented in HIP-0026.
//
// In split-deploy mode (legacy ghcr.io/hanzoai/gateway image) the
// gateway runs as its own legacy-engine process — the standalone cmd/gateway
// binary keeps that path. The Mount path below is the SAME logic,
// reused inside the cloud binary so we do not maintain two trust
// boundaries.
package gateway

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/hanzoai/authz/edge"
	"github.com/hanzoai/gateway/v2/token"
	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

// MountDeps is the whole of what the boundary needs from whoever installs it —
// alongside RouterDeps (BuildApp) and RelayDeps (RegisterRelay), one narrow
// shape per entrypoint, all three declared in this module.
//
// It was the HOST's own cloud.Deps: 24 fields carried across the boundary to
// reach three. The other 21 were not unused so much as untyped coupling, and
// coupling to a NAME rather than to a value — hanzoai/cloud ships two editions
// under one module path, so cloud.Deps denotes a different type in each, and a
// package that takes it can be composed by exactly one of them. Which one is
// decided by whichever edition happens to be in the build, not by anything this
// package says.
//
// Naming the three values instead turns the arrow around: the host knows the
// gateway, and the gateway knows zip and nothing of whoever runs it.
type MountDeps struct {
	// Logger receives the mount's own lifecycle lines. Required — Mount refuses
	// a nil one rather than dropping the record of what boundary it installed.
	Logger luxlog.Logger
	// Brand is the white-label deployment id ("hanzo", "lux", "zoo", ...). The
	// boundary derives NO behaviour from it; it is logged so an operator can see
	// which deployment's edge came up.
	Brand string
	// Domain is the deployment's own public API host (api.hanzo.ai,
	// api.lux.network). It supplies the default JWKS URL when JWKS_URL is unset,
	// which is the one decision this value drives.
	Domain string
}

// Mount registers the gateway subsystem on app per HIP-0106. The mount
// does three things:
//
//  1. Installs the canonical zip gate chain — CORS, then the trust
//     boundary (strip client-supplied identity headers, validate JWT,
//     write X-* headers), then the widget-key gate — so every downstream
//     subsystem on the same zip.App sees one clean boundary, and the same
//     one the legacy edge applies.
//
//  2. Parses the gateway routes table (KMS or local file) when one is
//     configured. Its reader is the standalone edge's transport, NOT this
//     mount: co-resident, the routing source of truth is cloud's own mount
//     table (routes.go states why in full). Loading it here is a Phase-C
//     hook and a config validation, not a routing decision.
//
//  3. Exposes /_/gateway/healthz on the native zip surface so liveness
//     probes work even with auth fully enabled.
//
// Mount installs onto the HOST's App and returns nothing, which is the whole
// difference between this subsystem and one that contributes routes. A child
// App's Use-chain is scoped to that child's own subtree (zip's snapshot
// semantics), so a gateway that built and returned its own App would guard its
// two probes and leave every sibling subsystem on the host unguarded — the
// boundary would still be there, still tested, and no longer on the path.
// Composition by return value is right for a subsystem that OWNS a prefix;
// this one owns the whole edge.
//
// Mount is not idempotent — calling it twice on the same App installs the
// middleware twice. A host lists the gateway once.
func Mount(app *zip.App, deps MountDeps) error {
	if app == nil {
		return fmt.Errorf("gateway.Mount: nil zip.App")
	}
	logger := deps.Logger
	if logger == nil {
		return fmt.Errorf("gateway.Mount: nil deps.Logger")
	}

	// Build the auth config from env. The standalone gateway binary
	// reads the same vars; the unified binary inherits them so split
	// vs. co-resident deployments stay byte-identical on the trust
	// boundary.
	authCfg := authConfigFromEnv(deps)
	if err := authCfg.Validate(); err != nil {
		return fmt.Errorf("gateway.Mount: %w", err)
	}

	// The gates, NATIVE, in the order the legacy engine runs them
	// (legacy_engine.go): CORS before routing, then the trust boundary, then the
	// widget-key gate — which is documented as running after auth and does.
	//
	// They are the SAME policy values the legacy edge runs, reached without a
	// framework in between. Two of the three had no zip transport at all, so the
	// HIP-0106 boundary answered no preflight and enforced no widget-key origin
	// or rate limit; transport_parity_test.go is what stops them drifting again.
	app.Use(
		zipCORS(newCORSPolicy()),
		zipAuth(authCfg),
		zipWidget(DefaultWidgetSecurityConfig()),
	)

	// The probes, as TYPED ops, under this subsystem's own reserved prefix —
	// the same two ops the standalone binary serves at its root (probes.go).
	//
	// They sit BEHIND the boundary, as the single healthz here always has: the
	// gate admits a tokenless request unless AUTH_REQUIRE=true, and it never
	// reaches JWKS for a request carrying no credential, so a misconfigured
	// signing-key URL cannot fail a liveness answer.
	MountProbes(app)

	// Routes table — best-effort load. A missing routes file is not
	// fatal in cloud-mode: every other subsystem is in-process and the
	// gateway routes table is only used for the truly external paths
	// (third-party APIs proxied at the edge). The standalone gateway
	// binary fails closed; cloud-mode logs and continues.
	if err := loadRoutesBestEffort(logger); err != nil {
		logger.Warn("gateway routes not loaded; co-resident subsystems still served",
			"err", err)
	}

	logger.Info("gateway mounted",
		"auth.enabled", authCfg.Enabled,
		"auth.issuer", authCfg.Issuer,
		"auth.require", authCfg.RequireAuth,
		"brand", deps.Brand,
		"domain", deps.Domain,
	)
	return nil
}

// zipAuth is the trust boundary as a NATIVE zip handler: it reads the request's
// own fasthttp headers, hands them to the one policy (authpolicy.go), and
// either answers the refusal or continues.
//
// It replaces zipFromGin, which stood up a whole gin engine per request and
// bridged through fiber's net/http adapter to reach a decision that never
// needed gin. That bridge was not merely slow — it was WRONG, and silently:
// fiber's adaptor copies the middleware's headers back onto the fasthttp
// request with Set and never Del, so every header the strip DELETED came back.
// A client-supplied X-User-IsAdmin, X-Org-Id or X-User-Permissions survived
// this trust boundary intact, on the exact path whose entire job is to remove
// it. Reading and writing the request's own headers in place is both the fix
// and the reason there is nothing left to get wrong: there is no copy.
func zipAuth(cfg AuthConfig) zip.Handler {
	gate := newAuthGate(cfg)
	return func(c *zip.Ctx) error {
		req := c.Fiber().Request()
		if r := gate.admit(c.Method(), c.Host(), c.Path(), newFastHeaders(&req.Header)); r != nil {
			return c.JSON(r.Status, r.Body)
		}
		return c.Continue()
	}
}

// zipWidget is the widget-key gate ([widgetGate.admit]) as a NATIVE zip handler.
// It reads; it never writes identity, so it cannot affect the trust boundary
// above it — the only thing it can do is refuse.
//
// The gate is built ONCE, out here: newWidgetGate starts the limiter's eviction
// goroutine, and a gate per request would also mean a rate-limit window per
// request, which is no rate limit at all.
//
// Fiber's IP() is the SOCKET peer here — zip's fiber.Config sets no ProxyHeader,
// so it returns fasthttp's RemoteIP and reads no forwarded header. That is
// exactly what the gate wants: behind hanzoai/ingress the peer alone would bucket
// every request in the cluster together, so clientip.go walks the forwarded chain
// from it under one trusted-proxy policy — the same one the gin transport gets.
func zipWidget(cfg WidgetSecurityConfig) zip.Handler {
	gate := newWidgetGate(cfg)
	return func(c *zip.Ctx) error {
		req := c.Fiber().Request()
		if r := gate.admit(edge.Of(&req.Header), c.Fiber().IP()); r != nil {
			return c.JSON(r.Status, r.Body)
		}
		return c.Continue()
	}
}

// zipCORS is the CORS policy ([corsPolicy]) as a NATIVE zip handler: reflect an
// allowlisted Origin with credentials, answer a preflight 204, and give a
// non-allowlisted Origin nothing at all.
//
// It runs FIRST so a preflight is answered before the trust boundary can refuse
// it: a browser sends OPTIONS without the Authorization header, so an
// auth-gated preflight 401s and the real request is never sent — which reads as
// a CORS failure and is really an ordering bug. The legacy engine orders it the
// same way, for the same reason.
func zipCORS(policy corsPolicy) zip.Handler {
	return func(c *zip.Ctx) error {
		a := policy.admit(c.Header("Origin"))
		if a == nil {
			return c.Continue()
		}
		a.credentials(c.SetHeader)
		if c.Method() == http.MethodOptions {
			a.negotiation(c.Header("Access-Control-Request-Headers"), c.SetHeader)
			return c.NoContent(http.StatusNoContent)
		}
		return c.Continue()
	}
}

// authConfigFromEnv builds the gateway AuthConfig from env, applying
// deployment defaults derived from deps when env is unset.
func authConfigFromEnv(deps MountDeps) AuthConfig {
	// Audience allowlist: the shared known-client_id + origin set
	// (token.AudiencesFromEnv, overridable via GATEWAY_ALLOWED_AUDIENCES).
	// A JWT_AUDIENCE override widens the set (parity with AUTH_AUDIENCE) — it
	// never narrows it to one value, which would reject every user JWT.
	audiences := token.AudiencesFromEnv()
	if a := strings.TrimSpace(getenv("JWT_AUDIENCE", "")); a != "" {
		audiences = appendUniqueAud(audiences, a)
	}
	cfg := AuthConfig{
		Enabled:        authEnabled(),
		JWKSURL:        getenv("JWKS_URL", "https://"+deps.Domain+"/v1/iam/.well-known/jwks"),
		Issuer:         getenv("JWT_ISSUER", "https://hanzo.id"),
		Audiences:      audiences,
		BillingURL:     getenv("AUTH_BILLING_URL", "http://commerce.hanzo.svc.cluster.local:8001"),
		BillingToken:   getenv("COMMERCE_SERVICE_TOKEN", ""),
		BillingEnabled: getenv("BILLING_ENABLED", "false") == "true",
		BillingPaths:   splitCSV(getenv("BILLING_PATHS", "")),
		RequireAuth:    getenv("AUTH_REQUIRE", "false") == "true",
	}
	if hosts := getenv("AUTH_PUBLIC_HOSTS", ""); hosts != "" {
		cfg.PublicHosts = splitCSV(hosts)
	}
	if paths := getenv("AUTH_PUBLIC_PATHS", ""); paths != "" {
		cfg.PublicPaths = splitCSV(paths)
	}
	return cfg
}

func loadRoutesBestEffort(logger interface {
	Info(msg string, ctx ...any)
	Warn(msg string, ctx ...any)
}) error {
	path := getenv("GATEWAY_ROUTES_FILE", "")
	if path == "" {
		// No file configured — leave the routes table empty. Co-resident
		// subsystems own their own routes via their Mount().
		return nil
	}
	return LoadRoutesFromFile(path)
}

func getenv(key, dflt string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return dflt
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// appendUniqueAud appends v to the audience list unless already present.
func appendUniqueAud(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}
