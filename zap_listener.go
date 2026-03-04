package gateway

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
)

// ZapListenerConfig configures the inbound ZAP listener for external clients.
type ZapListenerConfig struct {
	Port     int
	CertFile string
	KeyFile  string
	// InternalAddr is the local ZAP node's address to proxy to (e.g. "127.0.0.1:9652").
	InternalAddr string
}

var (
	zapListenerLn net.Listener
	zapListenerMu sync.Mutex
)

// StartZapListener starts a TLS 1.3+PQ listener on the given port.
// External clients (e.g. dev CLI) connect here with TLS-wrapped ZAP binary.
// Each accepted TLS connection is transparently proxied to the internal ZAP
// node (started by the ZapBackendFactory pool on the internal port), which
// handles the ZAP handshake, message dispatch, and forwarding to cloud-api.
func StartZapListener(cfg ZapListenerConfig) error {
	if cfg.Port == 0 {
		cfg.Port = 9651
	}
	if cfg.InternalAddr == "" {
		cfg.InternalAddr = "127.0.0.1:9652"
	}

	// Load TLS certificate.
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("zap-listener: load cert: %w", err)
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, // PQ hybrid (Go 1.24+)
			tls.X25519,         // fallback
		},
		Certificates: []tls.Certificate{cert},
	}

	// Start TLS listener.
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", cfg.Port), tlsCfg)
	if err != nil {
		return fmt.Errorf("zap-listener: listen :%d: %w", cfg.Port, err)
	}

	zapListenerMu.Lock()
	zapListenerLn = ln
	zapListenerMu.Unlock()

	slog.Info("ZAP listener started", "port", cfg.Port, "tls", "1.3+PQ", "internal", cfg.InternalAddr)

	// Accept loop — proxy each TLS connection to the internal ZAP node.
	go func() {
		for {
			extConn, err := ln.Accept()
			if err != nil {
				return // Listener closed.
			}
			go proxyZapConn(extConn, cfg.InternalAddr)
		}
	}()

	return nil
}

// proxyZapConn connects to the internal ZAP node and bidirectionally copies data.
func proxyZapConn(extConn net.Conn, internalAddr string) {
	defer extConn.Close()

	intConn, err := net.Dial("tcp", internalAddr)
	if err != nil {
		slog.Warn("ZAP proxy: connect internal", "error", err, "addr", internalAddr)
		return
	}
	defer intConn.Close()

	done := make(chan struct{})
	go func() {
		io.Copy(intConn, extConn)
		close(done)
	}()
	io.Copy(extConn, intConn)
	<-done
}

// StopZapListener gracefully shuts down the ZAP TLS listener.
func StopZapListener() {
	zapListenerMu.Lock()
	defer zapListenerMu.Unlock()

	if zapListenerLn != nil {
		zapListenerLn.Close()
		zapListenerLn = nil
	}
}

// InitZapListenerFromEnv initializes the ZAP listener from environment variables.
// Set ZAP_LISTENER_ENABLED=true to enable.
func InitZapListenerFromEnv() {
	if os.Getenv("ZAP_LISTENER_ENABLED") != "true" {
		return
	}

	port := 9651
	if p := os.Getenv("ZAP_LISTENER_PORT"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	cfg := ZapListenerConfig{
		Port:         port,
		CertFile:     os.Getenv("ZAP_TLS_CERT"),
		KeyFile:      os.Getenv("ZAP_TLS_KEY"),
		InternalAddr: os.Getenv("ZAP_INTERNAL_ADDR"),
	}

	if cfg.CertFile == "" {
		cfg.CertFile = "/etc/tls/tls.crt"
	}
	if cfg.KeyFile == "" {
		cfg.KeyFile = "/etc/tls/tls.key"
	}

	if err := StartZapListener(cfg); err != nil {
		slog.Error("ZAP listener init failed", "error", err)
	}
}
