// Copyright © 2026 Hanzo AI. MIT License.

// cmd/gateway is the standalone Hanzo Gateway edge process per HIP-0110.
//
// One binary, three responsibilities:
//
//  1. Terminate the JSON/HTTP boundary on :8080 for every external client.
//  2. Validate JWTs against IAM and mint the canonical identity header set
//     (X-Org-Id, X-User-Id, X-User-IsAdmin, X-User-Permissions, X-Roles,
//     X-User-Email, X-Phone-Number) per HIP-0026.
//  3. Forward the validated request to cloud (HIP-0106) over ZAP, and
//     route ZAP push frames from base back to the originating client as
//     SSE/WebSocket bytes — no JSON re-marshaling on the reverse path.
//
// The gateway holds no per-tenant state. Per-replica memory is bounded by
// open connection count plus the JWKS cache; horizontal scaling is a
// replica-count knob with no sticky sessions.
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

	"github.com/hanzoai/gateway"
	"github.com/hanzoai/zip"
	"github.com/hanzoai/zip/middleware"
)

const (
	envListen       = "GATEWAY_LISTEN"
	envHealthListen = "GATEWAY_HEALTH_LISTEN"
	envCloudZAPAddr = "CLOUD_ZAP_ADDR"
	envBaseZAPAddr  = "BASE_ZAP_ADDR"
	envNodeID       = "GATEWAY_NODE_ID"

	defaultListen       = ":8080"
	defaultHealthListen = ":8081"
	defaultCloudAddr    = "cloud:9090"
	defaultBaseAddr     = "base:9091"

	shutdownGrace = 30 * time.Second
)

func main() {
	logger := luxlog.New("service", "gateway")
	cfg := loadConfig(logger)

	zapNode, err := dialBackends(logger, cfg)
	if err != nil {
		logger.Error("backend dial failed", "err", err)
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
		if err := app.Listen(cfg.Listen); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("public listen: %w", err)
		}
	}()
	go func() {
		logger.Info("health listener up", "addr", cfg.HealthListen)
		if err := health.Listen(cfg.HealthListen); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("health listen: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received", "grace", shutdownGrace.String())
	case err := <-errCh:
		logger.Error("listener exited", "err", err)
	}

	drainCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
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

type config struct {
	Listen, HealthListen string
	CloudZAPAddr, BaseZAPAddr, NodeID string
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

func dialBackends(logger luxlog.Logger, cfg config) (*zaplib.Node, error) {
	node := zaplib.NewNode(zaplib.NodeConfig{
		NodeID:      cfg.NodeID,
		Port:        0,
		NoDiscovery: true,
		Logger:      slog.Default(),
	})
	if err := node.Start(); err != nil {
		return nil, fmt.Errorf("zap node start: %w", err)
	}
	if err := node.ConnectDirect(cfg.CloudZAPAddr); err != nil {
		node.Stop()
		return nil, fmt.Errorf("dial cloud %s: %w", cfg.CloudZAPAddr, err)
	}
	if err := node.ConnectDirect(cfg.BaseZAPAddr); err != nil {
		node.Stop()
		return nil, fmt.Errorf("dial base %s: %w", cfg.BaseZAPAddr, err)
	}
	node.Handle(gateway.MsgTypePush, gateway.HandleReversePush)
	logger.Info("zap backends connected",
		"cloud", cfg.CloudZAPAddr,
		"base", cfg.BaseZAPAddr,
	)
	return node, nil
}

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
		c.SetHeader("Content-Type", "text/plain; version=0.0.4")
		return c.SendString(http.StatusOK, "# gateway up\n")
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
