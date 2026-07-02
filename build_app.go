// Copyright © 2026 Hanzo AI. MIT License.

// build_app.go wires the gateway edge per HIP-0110.
//
// The gateway is a pure ZAP→ZAP relay: ingress terminates TLS+HTTP and
// speaks ZAP to the gateway; the gateway authenticates on the Forward
// ENVELOPE, injects identity, and forwards to cloud/base over ZAP. The
// relay therefore lives on the ZAP node (RegisterRelay), not on an HTTP
// router — there is no per-request HTTP handling at the gateway anymore.
//
// BuildApp still returns a tiny *zip.App so cmd/gateway/main can keep its
// :8080 listener as a process/liveness surface (ingress owns real client
// HTTP). It carries no forwarder and no auth middleware — those moved onto
// the node. RegisterRelay is the real entrypoint.
package gateway

import (
	"errors"
	"net/http"
	"time"

	luxlog "github.com/luxfi/log"
	zaplib "github.com/luxfi/zap"
	"github.com/luxfi/zap/forward"

	"github.com/zap-proto/zip"
	"github.com/zap-proto/zip/middleware"
)

// jwksTTL is the signing-key cache lifetime for the relay gate. Matches the
// edge cache used elsewhere; keys refresh past this, stale-on-error.
const jwksTTL = 5 * time.Minute

// RouterDeps is the set of dependencies BuildApp needs.
type RouterDeps struct {
	Logger    luxlog.Logger
	ZAPNode   *zaplib.Node
	CloudAddr string
	BaseAddr  string
}

// RelayDeps is what RegisterRelay needs to stand up the ZAP relay on a node.
type RelayDeps struct {
	Logger luxlog.Logger
	Node   *zaplib.Node
	// Pick chooses the backend peer for a request path. Production passes a
	// lazy resolver-backed picker (peerResolver.picker) that dials backends
	// on first use, so the gateway boots even when the backends are absent.
	// When nil, RegisterRelay falls back to the static pickPeer over the
	// pre-resolved BasePeerID / CloudPeerID below.
	Pick forward.PeerPicker
	// BasePeerID / CloudPeerID are the handshake-learned NodeIDs of the
	// already-connected base and cloud peers (from ConnectDirectID at dial
	// time). Used only when Pick is nil (e.g. tests that dial up front).
	BasePeerID  string
	CloudPeerID string
	// Auth is the IAM JWT validation config for the relay gate. Use
	// DefaultAuthConfig() to read it from the environment.
	Auth AuthConfig
}

// RegisterRelay installs the canonical HIP-0110 relay on deps.Node:
//
//   - forward.Relay(node, gate, pick): decodes each inbound Forward
//     envelope, runs the auth gate on it (JWT validate + identity inject,
//     NO body read, NO billing — cloud bills the bridged request),
//     re-emits the Forward with identity, and forwards to the picked peer,
//     streaming the backend's Response back verbatim.
//   - forward.RegisterReversePushHandler(node): routes backend→gateway
//     Push frames (SSE / WebSocket) back to the originating client conn.
//
// The gate reuses package iamauth + gateway's permission bit-field math;
// there is exactly one auth implementation. pick routes /v1/base/* to the
// base peer, everything else to cloud.
func RegisterRelay(deps RelayDeps) error {
	if deps.Logger == nil {
		return errors.New("gateway.RegisterRelay: nil Logger")
	}
	if deps.Node == nil {
		return errors.New("gateway.RegisterRelay: nil Node")
	}

	gate := newGate(deps.Auth)
	pick := deps.Pick
	if pick == nil {
		pick = pickPeer(deps.BasePeerID, deps.CloudPeerID)
	}

	forward.Relay(deps.Node, gate, pick)
	forward.RegisterReversePushHandler(deps.Node)

	deps.Logger.Info("gateway relay registered",
		"lazy_picker", deps.Pick != nil,
		"base_peer", deps.BasePeerID,
		"cloud_peer", deps.CloudPeerID,
		"auth_enabled", deps.Auth.Enabled,
		"require_auth", deps.Auth.RequireAuth,
	)
	return nil
}

// BuildApp returns the gateway's tiny HTTP surface for cmd/gateway/main's
// :8080 listener. Real client traffic arrives over ZAP via RegisterRelay;
// this app exists only so the process exposes a liveness/readiness HTTP
// endpoint on the public port. It carries no forwarder.
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
	)
	app.Get("/healthz", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	app.Get("/readyz", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ready"})
	})
	deps.Logger.Info("gateway.BuildApp ready (relay on ZAP node; HTTP is liveness-only)",
		"cloud_zap", deps.CloudAddr, "base_zap", deps.BaseAddr)
	return app, nil
}
