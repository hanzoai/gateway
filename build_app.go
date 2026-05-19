// Copyright © 2026 Hanzo AI. MIT License.

// build_app.go is the gateway router entrypoint per HIP-0110.
//
// gateway.BuildApp constructs the public-facing *zip.App that
// cmd/gateway/main wires onto :8080. It composes the canonical zip
// middleware stack (request-id, recover, CORS, logging) with the
// gateway-owned auth middleware (JWT validate + identity-header
// mint, landing on feat/own-auth-middleware in
// github.com/hanzoai/gateway/middleware) and a catch-all forwarder
// that turns every inbound request into a ZAP Forward envelope.
//
// The bulk of the catch-all forwarder, telemetry, rate-limit, and
// realtime-subscribe routes land in their own files on this branch.
// This file holds only the entrypoint shape so the standalone main
// has something to call.
package gateway

import (
	"errors"
	"fmt"
	"net/http"

	luxlog "github.com/luxfi/log"
	zaplib "github.com/luxfi/zap"

	"github.com/hanzoai/zip"
	"github.com/hanzoai/zip/middleware"
)

// RouterDeps is the set of dependencies the gateway router needs to
// stand itself up. cmd/gateway/main constructs and passes this in.
type RouterDeps struct {
	Logger    luxlog.Logger
	ZAPNode   *zaplib.Node
	CloudAddr string
	BaseAddr  string
}

// BuildApp returns the public *zip.App that listens on the gateway's
// :8080 public port. It is intentionally not split into many small
// constructors — gateway is small enough that one builder reads as
// the whole router contract.
//
// The auth middleware lives in github.com/hanzoai/gateway/middleware
// (landing on feat/own-auth-middleware) and is imported here once that
// branch merges. Until then BuildApp installs the canonical zip stack
// only; the JWT-validation + identity-header mint layer is wired by
// the in-flight branch.
func BuildApp(deps RouterDeps) (*zip.App, error) {
	if deps.Logger == nil {
		return nil, errors.New("gateway.BuildApp: nil Logger")
	}
	if deps.ZAPNode == nil {
		return nil, errors.New("gateway.BuildApp: nil ZAPNode")
	}

	app := zip.New(zip.Config{
		Logger:                deps.Logger,
		ServerHeader:          "hanzoai",
		DisableStartupMessage: true,
		AppName:               "gateway",
	})

	// Canonical zip middleware. Order matters:
	//   Recover  — first, so a panic in any later middleware is caught.
	//   RequestID — early, so logs and downstream calls carry the id.
	//   Logger    — wraps every request with method/path/status/duration.
	//   CORS      — must run before any auth check; preflights need 204
	//               without JWT validation.
	app.Use(
		middleware.Recover(),
		middleware.RequestID(),
		middleware.Logger(deps.Logger),
		middleware.CORS(middleware.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowHeaders: []string{
				"Content-Type",
				"Authorization",
				"X-Request-Id",
			},
		}),
	)

	// Auth middleware: landed by feat/own-auth-middleware as
	// github.com/hanzoai/gateway/middleware.Auth(...). Once that PR
	// merges, this builder will Use() it here. The trust-boundary
	// strip+mint contract is enforced there.

	// Catch-all forwarder: any path not handled by a gateway-local
	// route (health, openapi, realtime upgrade) gets wrapped into a
	// ZAP Forward envelope and dispatched to the right backend. The
	// forwarder uses deps.ZAPNode.Call(peer, msg) for synchronous
	// REST and deps.ZAPNode.Send for streaming.
	//
	// The catch-all itself lives in forwarder.go on this branch; this
	// builder only wires the entry point. Until forwarder.go lands we
	// fall through to 503 so the binary is observable end-to-end.
	app.All("/*", func(c *zip.Ctx) error {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error":   "gateway forwarder not yet wired",
			"backend": pickBackend(c.Path(), deps),
		})
	})

	deps.Logger.Info("gateway.BuildApp ready",
		"cloud_zap", deps.CloudAddr,
		"base_zap", deps.BaseAddr,
	)
	return app, nil
}

// pickBackend chooses the ZAP peer for a given path. /v1/base/*
// routes go to base; everything else (iam, kms, ai, commerce, vfs,
// mq, o11y, mcp, authz, ...) goes to cloud, which dispatches to the
// right in-process subsystem per HIP-0106.
func pickBackend(path string, deps RouterDeps) string {
	if hasPrefix(path, "/v1/base/") {
		return deps.BaseAddr
	}
	return deps.CloudAddr
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

// ensure linkage is exercised (the standalone main imports the
// gateway package only for the constants + funcs below; this var
// pins the import path so accidental refactors break loud).
var _ = fmt.Sprint
