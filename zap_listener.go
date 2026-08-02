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
// handles the ZAP handshake, message dispatch, and forwarding to cloud.
func StartZapListener(cfg ZapListenerConfig) error {
	if cfg.Port == 0 {
		// THE public ZAP port — see zaplisten.go, which is where this number is
		// decided for the whole process. 9651 was a Lux leak (Lux staking port).
		// Real peer resolution is mDNS-dynamic per HIP-0069; this fixed value is
		// only the fallback when discovery is off.
		cfg.Port = zapPublicPort
	}
	if cfg.InternalAddr == "" {
		cfg.InternalAddr = zapInternalAddr
	}

	// SELF-DIAL GUARD. This listener binds ":port", i.e. EVERY interface, and
	// then proxies each accepted connection to InternalAddr — so if InternalAddr
	// names the same port, every accepted connection is handed straight back to
	// this listener, whatever host it names.
	//
	// crypto/tls defers the handshake to the first Read, so Accept returns before
	// any certificate is exchanged: ONE bare TCP SYN, unauthenticated, starts an
	// unbounded accept -> self-dial -> accept loop, two fds and a goroutine per
	// turn, on the pod that also serves api.hanzo.ai. That is not a tuning
	// mistake to be discovered one accept at a time; it is a misconfiguration
	// that can be refused at startup, so it is.
	//
	// The production manifest had exactly this shape: k8s/hanzo/deployment.yaml
	// set ZAP_LISTENER_PORT=9999 and ZAP_INTERNAL_ADDR=127.0.0.1:9999.
	internalHost, internalPort, err := net.SplitHostPort(cfg.InternalAddr)
	if err != nil {
		return fmt.Errorf("zap-listener: internal address %q is not host:port: %w", cfg.InternalAddr, err)
	}
	if internalPort == fmt.Sprint(cfg.Port) {
		return fmt.Errorf(
			"zap-listener: refusing to start — it would forward to itself: "+
				"listening on :%d and proxying to %s (same port). "+
				"The plaintext ZAP server belongs on %s; give ZAP_INTERNAL_ADDR that address",
			cfg.Port, cfg.InternalAddr, zapInternalAddr)
	}
	// The inward leg is plaintext (there is no TLS ZAP dialer anywhere in the
	// fleet), so a non-loopback InternalAddr sends decrypted traffic back onto
	// the network. Refuse that too: this listener exists to BE the crypto.
	if !isLoopbackHost(internalHost) {
		return fmt.Errorf(
			"zap-listener: refusing to start — internal address %q is not loopback. "+
				"This proxy forwards DECRYPTED bytes there over plaintext ZAP, so a routable "+
				"host puts cleartext back on the wire; %s is the address it is meant to have",
			cfg.InternalAddr, zapInternalAddr)
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

	port := zapPublicPort // see zaplisten.go (was 9651 — a Lux staking-port leak)
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
