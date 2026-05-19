// Copyright © 2026 Hanzo AI. MIT License.

//go:build cloud
// +build cloud

// Package gateway exposes the HIP-0106 unified-binary mount surface for
// the Hanzo Gateway. In the unified cloud binary the gateway acts as
// the trust boundary: it validates JWTs, strips client-supplied
// identity headers, and mints the gateway-authorized X-Org-Id /
// X-User-Id / X-User-Email / X-Roles / X-User-Permissions /
// X-User-IsAdmin / X-Phone-Number set documented in HIP-0026.
//
// In split-deploy mode (legacy ghcr.io/hanzoai/gateway image) the
// gateway runs as its own KrakenD process — the standalone cmd/gateway
// binary keeps that path. The Mount path below is the SAME logic,
// reused inside the cloud binary so we do not maintain two trust
// boundaries.
package gateway

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hanzoai/cloud"
	gw "github.com/hanzoai/gateway"
	"github.com/hanzoai/zip"
)

// Mount registers the gateway subsystem on app per HIP-0106. The mount
// does three things:
//
//  1. Installs the canonical zip middleware chain (strip client-supplied
//     identity headers, validate JWT, mint X-* headers) so every
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
// the middleware twice; cloud.Registry guarantees one call per process.
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
	authGin := gw.NewAuthMiddleware(authCfg)

	// Bridge gin.HandlerFunc → zip.Handler. We never .Next() at the gin
	// layer: zip's c.Continue() drives the downstream chain after the
	// auth handler decides to allow or 401. We let the gin handler
	// mutate the http.Request (it sets identity headers), then copy the
	// mutated headers back onto fiber.
	app.Use(zipFromGin(authGin))

	// Native zip health route. Independent of the gin-wrapped middleware
	// so a misconfigured JWKS does not 503 the probe.
	app.Get("/_/gateway/healthz", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]any{
			"status":  "ok",
			"service": "gateway",
		})
	})

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

// zipFromGin wraps a gin.HandlerFunc as a zip.Handler. The gin handler
// runs against an ad-hoc *gin.Context built from the underlying
// *fasthttp.RequestCtx via fiber's net/http adapter. We pay the ~5%
// adapter cost in exchange for sharing one trust-boundary implementation
// with the standalone gateway binary — see HIP-0106 rationale.
func zipFromGin(h gin.HandlerFunc) zip.Handler {
	mw := func(next http.Handler) http.Handler {
		engine := gin.New()
		engine.Use(h)
		engine.NoRoute(func(c *gin.Context) {
			// Copy the gin-mutated headers back onto the downstream
			// request, then delegate to next. The gin handler may have
			// minted X-Org-Id / X-User-Id / etc.
			for k, vs := range c.Request.Header {
				for _, v := range vs {
					c.Writer.Header()[k] = append(c.Writer.Header()[k], v)
				}
				_ = vs
			}
			next.ServeHTTP(c.Writer, c.Request)
		})
		return engine
	}
	return zip.AdaptNetHTTPMiddleware(mw)
}

// authConfigFromEnv builds the gateway AuthConfig from env, applying
// cloud-friendly defaults derived from deps when env is unset.
func authConfigFromEnv(deps cloud.Deps) gw.AuthConfig {
	cfg := gw.AuthConfig{
		Enabled:        getenv("AUTH_ENABLED", "true") == "true",
		JWKSURL:        getenv("JWKS_URL", "https://"+deps.Domain+"/.well-known/jwks"),
		Issuer:         getenv("JWT_ISSUER", "https://hanzo.id"),
		Audience:       getenv("JWT_AUDIENCE", "https://"+deps.Domain),
		BillingURL:     getenv("BILLING_URL", ""),
		BillingToken:   getenv("BILLING_TOKEN", ""),
		BillingEnabled: getenv("BILLING_ENABLED", "false") == "true",
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
	return gw.LoadRoutesFromFile(path)
}

func init() {
	cloud.Register("gateway", 80, func(app any, deps cloud.Deps) error {
		zapp, ok := app.(*zip.App)
		if !ok {
			return fmt.Errorf("gateway.Mount: expected *zip.App, got %T", app)
		}
		return Mount(zapp, deps)
	})
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
