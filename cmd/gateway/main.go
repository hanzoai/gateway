// Copyright © 2026 Hanzo AI. MIT License.

//go:build !legacy
// +build !legacy

// cmd/gateway is the standalone Hanzo Gateway edge process per HIP-0110.
//
// The gateway is a pure ZAP→ZAP relay. The production chain is:
//
//	ingress (TLS + HTTP→ZAP)  →  gateway (this: relay)  →  cloud/base
//
// One binary, three responsibilities:
//
//  1. Stand up an outbound ZAP node and connect it to cloud (HIP-0106) and
//     base, learning each peer's NodeID for routing.
//  2. Register the canonical relay (gateway.RegisterRelay → luxfi/zap
//     forward.Relay): authenticate every inbound Forward ENVELOPE — validate
//     the IAM JWT in its headers, inject the resolved identity (X-Org-Id,
//     X-User-Id, X-User-IsAdmin, X-User-Permissions) onto the envelope — and
//     forward to the picked backend, streaming the Response back verbatim.
//     The gate never reads the request body; billing is deferred to
//     cloud-api's own balance gate.
//  3. Route ZAP push frames from the backend back to the originating client
//     (SSE / WebSocket) via forward's reverse-push handler.
//
// Ingress terminates client HTTP; the gateway's own :8080 is a liveness HTTP
// surface only (gateway.BuildApp), and :8081 is the k8s health listener. The
// gateway holds no per-tenant state — per-replica memory is bounded by open
// connection count plus the JWKS cache; scaling is a replica-count knob with
// no sticky sessions.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	luxlog "github.com/luxfi/log"
	zaplib "github.com/luxfi/zap"

	"github.com/hanzoai/gateway/v2"
	"github.com/zap-proto/zip"
	"github.com/zap-proto/zip/middleware"
)

const (
	envListen       = "GATEWAY_LISTEN"
	envHealthListen = "GATEWAY_HEALTH_LISTEN"
	envCloudZAPAddr = "CLOUD_ZAP_ADDR"
	envBaseZAPAddr  = "BASE_ZAP_ADDR"
	envNodeID       = "GATEWAY_NODE_ID"

	defaultListen        = ":8080"
	defaultHealthListen  = ":8081"
	defaultCloudAddr     = "cloud:9090"
	defaultBaseAddr      = "base:9091"
	defaultShutdownGrace = 30 * time.Second
)

// shutdownGraceFromEnv parses GATEWAY_SHUTDOWN_TIMEOUT (any duration string
// accepted by time.ParseDuration, e.g. "45s", "2m"). Returns def when the
// env var is unset, empty, or unparseable. Operators driving slow rollouts
// (long-poll connections, large SSE backlogs) bump this above the default
// 30s; aggressive autoscalers can drop it.
func shutdownGraceFromEnv(def time.Duration) time.Duration {
	v := os.Getenv("GATEWAY_SHUTDOWN_TIMEOUT")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func main() {
	logger := luxlog.New("service", "gateway")
	cfg := loadConfig(logger)

	// startNode brings up the outbound ZAP node. Only a failure to start
	// the node itself is fatal — that is a local resource error (port
	// bind), not a dependency being absent. Reaching the cloud/base
	// backends is deferred to the relay's lazy picker so the gateway boots
	// and serves HTTP + healthz even when the backends don't exist yet
	// (HIP-0110: HTTP serving is what prod needs; ZAP connects on demand).
	zapNode, err := startNode(logger, cfg)
	if err != nil {
		logger.Error("zap node start failed", "err", err)
		os.Exit(1)
	}

	// The relay is the gateway's real work: it lives on the ZAP node, not
	// on an HTTP router. It authenticates each inbound Forward envelope,
	// injects identity, and forwards to base/cloud over ZAP. Billing is
	// deferred to cloud-api's own balance gate (HIP-0110). The picker dials
	// backends lazily on first use (and best-effort warms them now), so an
	// absent backend degrades only the requests routed to it, never boot.
	pick := gateway.NewLazyPicker(zapNode, logger, cfg.BaseZAPAddr, cfg.CloudZAPAddr)
	if err := gateway.RegisterRelay(gateway.RelayDeps{
		Logger: logger,
		Node:   zapNode,
		Pick:   pick,
		Auth:   gateway.DefaultAuthConfig(),
	}); err != nil {
		logger.Error("RegisterRelay failed", "err", err)
		zapNode.Stop()
		os.Exit(1)
	}

	app, err := gateway.BuildApp(gateway.RouterDeps{
		Logger:    logger,
		ZAPNode:   zapNode,
		CloudAddr: cfg.CloudZAPAddr,
		BaseAddr:  cfg.BaseZAPAddr,
	})
	if err != nil {
		logger.Error("BuildApp failed", "err", err)
		os.Exit(1)
	}

	health := buildHealthApp()

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)
	go func() {
		logger.Info("public listener up", "addr", cfg.Listen)
		if err := app.Listen("http://" + cfg.Listen); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("public listen: %w", err)
		}
	}()
	go func() {
		logger.Info("health listener up", "addr", cfg.HealthListen)
		if err := health.Listen("http://" + cfg.HealthListen); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("health listen: %w", err)
		}
	}()

	grace := shutdownGraceFromEnv(defaultShutdownGrace)
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received", "grace", grace.String())
	case err := <-errCh:
		logger.Error("listener exited", "err", err)
	}
	drainCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := app.ShutdownWithContext(drainCtx); err != nil {
		logger.Warn("public shutdown", "err", err)
	}
	if err := health.ShutdownWithContext(drainCtx); err != nil {
		logger.Warn("health shutdown", "err", err)
	}
	zapNode.Stop()
	logger.Info("gateway stopped")
}

// config holds the gateway's startup configuration. All fields come from
// env vars; the gateway has no on-disk config file by design.
type config struct {
	Listen       string
	HealthListen string
	CloudZAPAddr string
	BaseZAPAddr  string
	NodeID       string
}

func loadConfig(logger luxlog.Logger) config {
	cfg := config{
		Listen:       envOr(envListen, defaultListen),
		HealthListen: envOr(envHealthListen, defaultHealthListen),
		CloudZAPAddr: envOr(envCloudZAPAddr, defaultCloudAddr),
		BaseZAPAddr:  envOr(envBaseZAPAddr, defaultBaseAddr),
		NodeID:       envOr(envNodeID, hostnameOr("gateway")),
	}
	logger.Info("config",
		"listen", cfg.Listen,
		"health", cfg.HealthListen,
		"cloud_zap", cfg.CloudZAPAddr,
		"base_zap", cfg.BaseZAPAddr,
		"node_id", cfg.NodeID,
	)
	return cfg
}

// startNode constructs and starts the gateway's outbound ZAP node. It does
// NOT dial cloud/base — connecting to the backends is deferred to the
// relay's lazy picker (gateway.NewLazyPicker), which dials on first use and
// retries until a backend is reachable. This is the decomplected boot path:
// node startup (a local concern) is separated from backend reachability (a
// dependency concern) so an absent backend never blocks boot. The only
// failure returned here is a genuine local error — failure to bind the
// ephemeral port. The reverse-push handler is installed by
// gateway.RegisterRelay, not here.
func startNode(logger luxlog.Logger, cfg config) (*zaplib.Node, error) {
	node := zaplib.NewNode(zaplib.NodeConfig{
		NodeID:      cfg.NodeID,
		Port:        0, // ephemeral; gateway dials out, push flows back over same conn
		NoDiscovery: true,
		Logger:      slog.Default(),
	})
	if err := node.Start(); err != nil {
		return nil, fmt.Errorf("zap node start: %w", err)
	}
	logger.Info("zap node started (backends connect lazily on first use)",
		"cloud", cfg.CloudZAPAddr, "base", cfg.BaseZAPAddr)
	return node, nil
}

// buildHealthApp is the k8s liveness+readiness+metrics listener.
// Tiny on purpose: no auth, no JWT, no ZAP. A bare process check.
func buildHealthApp() *zip.App {
	app := zip.New(zip.Config{
		Logger:                luxlog.New("service", "gateway-health"),
		ServerHeader:          "-",
		DisableStartupMessage: true,
		AppName:               "gateway-health",
	})
	app.Use(middleware.Recover())
	app.Get("/healthz", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	app.Get("/readyz", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ready"})
	})
	app.Get("/metrics", func(c *zip.Ctx) error {
		// gateway.BuildApp installs the real Prometheus collector via
		// its telemetry middleware when GATEWAY_METRICS_ENABLED=true.
		// This stub keeps the path live for scrapers when telemetry
		// is off (dev/local).
		c.SetHeader("Content-Type", "text/plain; version=0.0.4")
		return c.String(http.StatusOK, "# gateway up\n")
	})
	return app
}

func envOr(key, dflt string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return dflt
}

func hostnameOr(dflt string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return dflt
}
