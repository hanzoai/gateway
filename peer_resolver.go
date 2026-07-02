// Copyright © 2026 Hanzo AI. Apache-2.0 License.

// peer_resolver.go decouples "where a backend lives" (its ZAP address)
// from "which connected NodeID forward.Relay must Call" (the handshake-
// learned peerID). HIP-0110's relay needs a peerID per request path, but
// a peerID is only knowable AFTER a successful ConnectDirectID handshake.
//
// The original boot path braided three concerns into dialBackends: start
// the node, eagerly dial both backends, and treat any dial failure as a
// fatal os.Exit. That made the gateway un-bootable whenever cloud:9090 /
// base:9091 were absent — which is the steady state in environments where
// the ZAP backends aren't deployed yet, while HTTP serving (the part prod
// actually needs) would work fine.
//
// peerResolver separates those concerns. The node is started once and
// unconditionally; dialing a backend is deferred to first use and retried
// on every Call until it succeeds. A backend being down degrades only the
// requests routed to it (they get a "peer not found" error that
// forward.Relay returns to the caller as a normal per-request failure),
// never the process. ConnectDirectID is idempotent — once a backend is
// reachable the first resolve caches its peerID and every subsequent
// resolve is a lock-free map read — so a healthy backend is dialed exactly
// once and ZAP behaves identically to the old eager path.
package gateway

import (
	"sync"

	zaplib "github.com/luxfi/zap"
	"github.com/luxfi/zap/forward"

	luxlog "github.com/luxfi/log"
)

// peerResolver lazily resolves a backend ZAP address to its connected
// peerID, dialing on demand and caching the learned NodeID. It is safe for
// concurrent use by the relay's per-request goroutines.
type peerResolver struct {
	node   *zaplib.Node
	logger luxlog.Logger

	mu      sync.Mutex        // serializes dials; guards peerIDs
	peerIDs map[string]string // addr -> handshake-learned peerID (once connected)
}

// newPeerResolver builds a resolver over an already-started node. It does
// not dial; the first resolve for an address performs the dial.
func newPeerResolver(node *zaplib.Node, logger luxlog.Logger) *peerResolver {
	return &peerResolver{
		node:    node,
		logger:  logger,
		peerIDs: make(map[string]string),
	}
}

// NewLazyPicker is the production seam: it builds a lazy resolver over an
// already-started node, best-effort warms the base and cloud backends (a
// failed warm is logged at WARN and ignored — the picker will retry on
// first use), and returns the forward.PeerPicker for RegisterRelay. The
// gateway boots regardless of backend reachability; healthy backends are
// dialed once here and served from cache thereafter.
func NewLazyPicker(node *zaplib.Node, logger luxlog.Logger, baseAddr, cloudAddr string) forward.PeerPicker {
	r := newPeerResolver(node, logger)
	r.warm("cloud", cloudAddr)
	r.warm("base", baseAddr)
	return r.picker(baseAddr, cloudAddr)
}

// warm best-effort dials addr to populate the cache ahead of first use, so
// the fast path is hot when the backend is present at boot. A failure is
// logged at WARN and swallowed: warming is an optimization, never a gate.
func (r *peerResolver) warm(name, addr string) {
	if addr == "" {
		return
	}
	if _, err := r.resolve(addr); err != nil {
		r.logger.Warn("zap backend not reachable at boot; will connect on first use",
			"backend", name, "addr", addr, "err", err)
		return
	}
	r.logger.Info("zap backend connected", "backend", name, "addr", addr)
}

// resolve returns the connected peerID for addr, dialing (and caching) on
// first use. ConnectDirectID is idempotent, so a cache miss that races with
// an existing connection still returns the right peerID without a second
// dial. The returned peerID is "" only when err != nil.
func (r *peerResolver) resolve(addr string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if id, ok := r.peerIDs[addr]; ok {
		return id, nil
	}
	peerID, err := r.node.ConnectDirectID(addr)
	if err != nil {
		return "", err
	}
	r.peerIDs[addr] = peerID
	return peerID, nil
}

// picker returns the forward.PeerPicker the relay calls per request. base
// addr handles /v1/base/*; everything else goes to cloud. On a dial failure
// the picker returns "" — node.Call("") yields a "peer not found" error
// that forward.Relay surfaces to that one caller as an HTTP error, never a
// process crash. The lazy dial is retried on the next matching request.
func (r *peerResolver) picker(baseAddr, cloudAddr string) forward.PeerPicker {
	return func(path string) string {
		addr := cloudAddr
		if isBasePath(path) {
			addr = baseAddr
		}
		peerID, err := r.resolve(addr)
		if err != nil {
			r.logger.Warn("zap backend dial failed; request will fail",
				"path", path, "addr", addr, "err", err)
			return ""
		}
		return peerID
	}
}
