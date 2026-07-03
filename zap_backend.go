//go:build legacy
// +build legacy

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/luxfi/zap"

	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
)

const (
	// ZapNamespace is the config key for ZAP backend configuration.
	ZapNamespace = "github.com/hanzoai/gateway/zap"

	// ZAP message types for gateway RPC
	MsgTypeHTTPRequest  uint16 = 200
	MsgTypeHTTPResponse uint16 = 201
)

// ZapConfig holds the ZAP backend configuration extracted from gateway.json.
type ZapConfig struct {
	// NodeID is the ZAP node ID for this service
	NodeID string `json:"node_id"`
	// PeerID is the ZAP node ID of the target backend
	PeerID string `json:"peer_id"`
	// PeerAddr is the direct address (host:port) if mDNS is disabled
	PeerAddr string `json:"peer_addr"`
	// ServiceType is the mDNS service type (e.g., "_hanzo._tcp")
	ServiceType string `json:"service_type"`
	// Port is the local ZAP port
	Port int `json:"port"`
	// Timeout is the request timeout in milliseconds
	Timeout int `json:"timeout_ms"`
	// NoDiscovery disables mDNS and uses direct connection
	NoDiscovery bool `json:"no_discovery"`
}

// zapNodePool manages ZAP node connections per backend.
var zapNodePool = struct {
	sync.RWMutex
	nodes map[string]*zap.Node
}{
	nodes: make(map[string]*zap.Node),
}

// getOrCreateNode returns a cached or new ZAP node for the given config.
func getOrCreateNode(cfg ZapConfig) (*zap.Node, error) {
	key := fmt.Sprintf("%s:%d", cfg.NodeID, cfg.Port)

	zapNodePool.RLock()
	if node, ok := zapNodePool.nodes[key]; ok {
		zapNodePool.RUnlock()
		return node, nil
	}
	zapNodePool.RUnlock()

	zapNodePool.Lock()
	defer zapNodePool.Unlock()

	// Double-check after acquiring write lock
	if node, ok := zapNodePool.nodes[key]; ok {
		return node, nil
	}

	node := zap.NewNode(zap.NodeConfig{
		NodeID:      cfg.NodeID,
		ServiceType: cfg.ServiceType,
		Port:        cfg.Port,
		NoDiscovery: cfg.NoDiscovery,
		Logger:      slog.Default(),
	})

	if err := node.Start(); err != nil {
		return nil, fmt.Errorf("zap: failed to start node: %w", err)
	}

	// If direct connection mode, connect immediately
	if cfg.NoDiscovery && cfg.PeerAddr != "" {
		if err := node.ConnectDirect(cfg.PeerAddr); err != nil {
			node.Stop()
			return nil, fmt.Errorf("zap: failed to connect to peer at %s: %w", cfg.PeerAddr, err)
		}
	}

	zapNodePool.nodes[key] = node
	return node, nil
}

// ZapBackendFactory wraps a standard BackendFactory and adds ZAP transport support.
// Backends with "github.com/hanzoai/gateway/zap" in their extra_config will use
// ZAP binary transport instead of HTTP.
func ZapBackendFactory(logger logging.Logger, next proxy.BackendFactory) proxy.BackendFactory {
	return func(remote *config.Backend) proxy.Proxy {
		v, ok := remote.ExtraConfig[ZapNamespace]
		if !ok {
			return next(remote)
		}

		// Parse ZAP config
		data, err := json.Marshal(v)
		if err != nil {
			logger.Error("[BACKEND: ZAP] Failed to marshal config:", err.Error())
			return next(remote)
		}

		var cfg ZapConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			logger.Error("[BACKEND: ZAP] Failed to parse config:", err.Error())
			return next(remote)
		}

		// Apply defaults
		if cfg.ServiceType == "" {
			cfg.ServiceType = "_hanzo._tcp"
		}
		if cfg.NodeID == "" {
			cfg.NodeID = "gateway"
		}
		if cfg.Port == 0 {
			// 9999 = canonical embedded-ZAP port. Peers are normally found via
			// mDNS (_hanzo._tcp); this fixed port is the NoDiscovery fallback.
			// Was 9651 — a Lux-leak (Lux staking port), removed per HIP-0069.
			cfg.Port = 9999
		}
		if cfg.Timeout == 0 {
			cfg.Timeout = 5000
		}

		node, err := getOrCreateNode(cfg)
		if err != nil {
			logger.Error("[BACKEND: ZAP] Failed to create node:", err.Error())
			return next(remote)
		}

		logger.Info(fmt.Sprintf("[BACKEND: ZAP] Using ZAP transport for %s → peer %s", remote.URLPattern, cfg.PeerID))

		return zapProxy(node, cfg, remote, logger)
	}
}

// zapProxy creates a proxy that sends requests over ZAP.
func zapProxy(node *zap.Node, cfg ZapConfig, remote *config.Backend, logger logging.Logger) proxy.Proxy {
	return func(ctx context.Context, request *proxy.Request) (*proxy.Response, error) {
		// Build ZAP message from the HTTP request
		b := zap.NewBuilder(1024)
		ob := b.StartObject(32) // method(0) + path(4) + headers(8) + body(12) + query(16)

		// Encode method
		method := request.Method
		if method == "" {
			method = http.MethodGet
		}
		ob.SetText(0, method)

		// Encode path
		path := remote.URLPattern
		for k, v := range request.Params {
			path = strings.ReplaceAll(path, "{"+k+"}", v)
		}
		ob.SetText(4, path)

		// Encode query string
		if len(request.Query) > 0 {
			queryParts := make([]string, 0, len(request.Query))
			for k, vals := range request.Query {
				for _, v := range vals {
					queryParts = append(queryParts, k+"="+v)
				}
			}
			ob.SetText(16, strings.Join(queryParts, "&"))
		}

		// Encode headers as JSON (compact)
		if len(request.Headers) > 0 {
			hdrs, _ := json.Marshal(request.Headers)
			ob.SetBytes(8, hdrs)
		}

		// Encode body
		if request.Body != nil {
			bodyBytes, err := io.ReadAll(request.Body)
			if err == nil && len(bodyBytes) > 0 {
				ob.SetBytes(12, bodyBytes)
			}
		}

		ob.FinishAsRoot()
		msg := b.Finish()

		zapMsg, err := zap.Parse(msg)
		if err != nil {
			return nil, fmt.Errorf("zap: failed to build message: %w", err)
		}

		// Send via ZAP with timeout
		timeout := time.Duration(cfg.Timeout) * time.Millisecond
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		resp, err := node.Call(callCtx, cfg.PeerID, zapMsg)
		if err != nil {
			logger.Error(fmt.Sprintf("[BACKEND: ZAP] Call to %s failed: %v", cfg.PeerID, err))
			return nil, err
		}

		// Parse response
		root := resp.Root()
		statusCode := int(root.Uint32(0))
		respBody := root.Bytes(4)
		respHdrsJSON := root.Bytes(8)

		// Parse response headers
		respHeaders := make(map[string][]string)
		if len(respHdrsJSON) > 0 {
			json.Unmarshal(respHdrsJSON, &respHeaders)
		}

		// Decode body into map
		var data map[string]interface{}
		if len(respBody) > 0 {
			json.Unmarshal(respBody, &data)
		}

		isComplete := statusCode >= 200 && statusCode < 300

		return &proxy.Response{
			Data:       data,
			IsComplete: isComplete,
			Metadata: proxy.Metadata{
				StatusCode: statusCode,
				Headers:    respHeaders,
			},
		}, nil
	}
}
