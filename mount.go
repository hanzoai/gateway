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
	"os"
	"strings"

	"github.com/hanzoai/cloud"
	"github.com/hanzoai/gateway/v2/token"
	"github.com/zap-proto/zip"
)

// Mount registers the gateway subsystem on app per HIP-0106. The mount
// does three things:
//
//  1. Installs the canonical zip middleware chain (strip client-supplied
//     identity headers, validate JWT, write X-* headers) so every
//     downstream subsystem on the same zip.App sees a clean trust
//     boundary.
//
//  2. Loads the gateway routes table (KMS or local file) so any path
//     not handled by a co-resident subsystem is proxied to the
//     configured backend.
//
//  3. Exposes /_/gateway/healthz on the native zip surface so liveness
//     probes work even with auth fully enabled.
//
// Mount is idempotent — calling it twice on the same App will install
// the middleware twice; the cloud composition root (apps.Wire) lists the
// gateway MountSpec once, so it is mounted exactly once per process.
func Mount(app *zip.App, deps cloud.Deps) error {
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

	// The trust boundary, NATIVE. It is the same policy the legacy edge runs
	// (authpolicy.go), reached without a framework in between.
	app.Use(zipAuth(authCfg))

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

// authConfigFromEnv builds the gateway AuthConfig from env, applying
// cloud-friendly defaults derived from deps when env is unset.
func authConfigFromEnv(deps cloud.Deps) AuthConfig {
	// Audience allowlist: the shared known-client_id + origin set
	// (token.AudiencesFromEnv, overridable via GATEWAY_ALLOWED_AUDIENCES).
	// A JWT_AUDIENCE override widens the set (parity with AUTH_AUDIENCE) — it
	// never narrows it to one value, which would reject every user JWT.
	audiences := token.AudiencesFromEnv()
	if a := strings.TrimSpace(getenv("JWT_AUDIENCE", "")); a != "" {
		audiences = appendUniqueAud(audiences, a)
	}
	cfg := AuthConfig{
		Enabled:        getenv("AUTH_ENABLED", "true") == "true",
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
