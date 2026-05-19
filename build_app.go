// Copyright © 2026 Hanzo AI. MIT License.

// build_app.go is the gateway router entrypoint per HIP-0110.
// gateway.BuildApp returns the public *zip.App that cmd/gateway/main
// wires onto :8080. Auth middleware (JWT validate + identity-header
// mint) is wired by feat/own-auth-middleware in
// github.com/hanzoai/gateway/middleware and added to this Use chain
// when that branch lands. The catch-all ZAP forwarder lives in
// forwarder.go on this branch.
package gateway

import (
	"errors"
	"net/http"
	"strings"

	luxlog "github.com/luxfi/log"
	zaplib "github.com/luxfi/zap"

	"github.com/hanzoai/zip"
	"github.com/hanzoai/zip/middleware"
)

// RouterDeps is the set of dependencies BuildApp needs.
type RouterDeps struct {
	Logger    luxlog.Logger
	ZAPNode   *zaplib.Node
	CloudAddr string
	BaseAddr  string
}

// BuildApp returns the public *zip.App for the gateway's :8080 port.
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
	app.Use(
		middleware.Recover(),
		middleware.RequestID(),
		middleware.Logger(deps.Logger),
		middleware.CORS(middleware.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowHeaders: []string{"Content-Type", "Authorization", "X-Request-Id"},
		}),
	)
	// Catch-all forwarder placeholder until forwarder.go lands.
	app.All("/*", func(c *zip.Ctx) error {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error":   "gateway forwarder not yet wired",
			"backend": pickBackend(c.Path(), deps),
		})
	})
	deps.Logger.Info("gateway.BuildApp ready",
		"cloud_zap", deps.CloudAddr, "base_zap", deps.BaseAddr)
	return app, nil
}

// pickBackend chooses the ZAP peer for path. /v1/base/* → base;
// everything else → cloud (which routes to per-HIP-0106 subsystems).
func pickBackend(path string, deps RouterDeps) string {
	if strings.HasPrefix(path, "/v1/base/") {
		return deps.BaseAddr
	}
	return deps.CloudAddr
}
