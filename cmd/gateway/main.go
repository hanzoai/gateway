// Copyright © 2026 Hanzo AI. MIT License.

// cmd/gateway is the standalone Hanzo Gateway edge process per HIP-0110.
// Terminates JSON/HTTP at :8080, validates JWTs, mints HIP-0026 identity
// headers, forwards every request to cloud/base over ZAP, and routes
// reverse-push frames from base back to client SSE/WS sockets.
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
	defaultListen       = ":8080"
	defaultHealthListen = ":8081"
	defaultCloudAddr    = "cloud:9090"
	defaultBaseAddr     = "base:9091"
	shutdownGrace       = 30 * time.Second
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
		Logger: logger, ZAPNode: zapNode,
		CloudAddr: cfg.CloudZAPAddr, BaseAddr: cfg.BaseZAPAddr,
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
	go listen(app, cfg.Listen, "public", logger, errCh)
	go listen(health, cfg.HealthListen, "health", logger, errCh)

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received", "grace", shutdownGrace.String())
	case err := <-errCh:
		logger.Error("listener exited", "err", err)
	}
	drainCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	_ = app.ShutdownWithContext(drainCtx)
	_ = health.ShutdownWithContext(drainCtx)
	zapNode.Stop()
	logger.Info("gateway stopped")
}

func listen(app *zip.App, addr, name string, logger luxlog.Logger, errCh chan<- error) {
	logger.Info(name+" listener up", "addr", addr)
	if err := app.Listen(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errCh <- fmt.Errorf("%s listen: %w", name, err)
	}
}

type config struct {
	Listen, HealthListen, CloudZAPAddr, BaseZAPAddr, NodeID string
}

func loadConfig(logger luxlog.Logger) config {
	cfg := config{
		Listen:       envOr("GATEWAY_LISTEN", defaultListen),
		HealthListen: envOr("GATEWAY_HEALTH_LISTEN", defaultHealthListen),
		CloudZAPAddr: envOr("CLOUD_ZAP_ADDR", defaultCloudAddr),
		BaseZAPAddr:  envOr("BASE_ZAP_ADDR", defaultBaseAddr),
		NodeID:       envOr("GATEWAY_NODE_ID", hostnameOr("gateway")),
	}
	logger.Info("config",
		"listen", cfg.Listen, "health", cfg.HealthListen,
		"cloud_zap", cfg.CloudZAPAddr, "base_zap", cfg.BaseZAPAddr,
		"node_id", cfg.NodeID)
	return cfg
}

// dialBackends opens one ZAP node and connects it to cloud and base.
// Reverse-push frames travel back over the same conns (zaplib dispatches
// any incoming MsgTypePush from any peer to the registered handler).
func dialBackends(logger luxlog.Logger, cfg config) (*zaplib.Node, error) {
	node := zaplib.NewNode(zaplib.NodeConfig{
		NodeID: cfg.NodeID, Port: 0, NoDiscovery: true,
		Logger: slog.Default(),
	})
	if err := node.Start(); err != nil {
		return nil, fmt.Errorf("zap node start: %w", err)
	}
	for name, addr := range map[string]string{"cloud": cfg.CloudZAPAddr, "base": cfg.BaseZAPAddr} {
		if err := node.ConnectDirect(addr); err != nil {
			node.Stop()
			return nil, fmt.Errorf("dial %s %s: %w", name, addr, err)
		}
	}
	node.Handle(gateway.MsgTypePush, gateway.HandleReversePush)
	logger.Info("zap backends connected",
		"cloud", cfg.CloudZAPAddr, "base", cfg.BaseZAPAddr)
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
		c.Fiber().Status(http.StatusOK)
		return c.Fiber().SendString("# gateway up\n")
	})
	return app
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func hostnameOr(d string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return d
}
