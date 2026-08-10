// Copyright © 2026 Hanzo AI. Apache-2.0 License.

// Package gateway is the Hanzo Gateway edge: the JWT trust boundary
// (identity strip + write), the host/path routing table, and the HIP-0106
// in-process mount surface consumed by the unified cloud binary.
//
// # Mount
//
// The canonical entrypoint is Mount, in mount.go at the module root:
//
//	func Mount(app *zip.App, deps MountDeps) error
//
// It carries NO build tag — it compiles in the default build. Mount installs
// the native zip gate chain (zipCORS, zipAuth, zipWidget), serves the typed
// probe pair under /_/gateway, and best-effort loads the routes table. A host
// calls it explicitly, not an init() and not a global registry.
//
// MountDeps is declared HERE, in three fields, and names no host. This package
// imports zip and nothing of whoever composes it: the dependency points from
// the host into the gateway, so any host can install this boundary and none of
// them can be the only one that compiles.
//
// # One policy per gate, two HTTP transports
//
// Every gate this edge applies is a framework-free VALUE, and each of the
// gateway's two HTTP edges is a few lines of adapter over it:
//
//	authGate.admit    authpolicy.go       strip, route class, public
//	                                      allowlists, token extraction, JWT
//	                                      validation, identity write, balance
//	widgetGate.admit  widget_security.go  hz_ origin allowlist + rate limits
//	corsPolicy.admit  cors.go             credentialed-origin allowlist
//
//	native zip   mount.go              zipAuth, zipWidget, zipCORS
//	gin          legacy_transports.go  the same three, for the Lura edge
//
// Mount installs all three in the order the legacy engine runs them, so the
// two edges cannot admit different requests. transport_parity_test.go drives
// one request through both and asserts they agree.
//
// The routing TABLE (routes.go) is the one thing with no zip twin: its
// compiled proxies are net/http, and reaching them from fasthttp would drop
// WebSocket upgrade and streaming. That file's header states it.
//
// # The HTTP surface
//
// The gateway owns two doors — liveness and readiness — and they are TYPED
// ops declared once in probes.go, mounted at the root by the standalone
// binary's two listeners and under /_/gateway by the cloud mount. /metrics
// is the one deliberate escape hatch (Prometheus exposition is text, not
// JSON); MountMetrics carries the reason. Everything else on the wire is a
// relay (gate.go) or a proxy (routes.go) and is somebody else's contract.
//
// # Build tags
//
// Two builds exist, and the one that SHIPS is `legacy`:
//
//	go build ./...               // default: no Lura; ZAP relay edge
//	go build -tags legacy ./...  // legacy: full Lura gin engine
//
// Makefile sets BUILD_TAGS ?= legacy and the Dockerfile runs `make build`,
// so ghcr.io/hanzoai/gateway is the legacy engine. The default build serves
// the probes until the HIP-0110 ZAP relay backends are live; see the
// rationale comment above BUILD_TAGS in the Makefile.
//
// The typed op table therefore reaches the DEFAULT binary (and the cloud
// binary through Mount) and NOT the legacy image, whose routes are the
// vendored Lura engine's. That is deliberate: internal/lura and
// internal/plugin are upstream KrakenD/Lura, and rewriting a fork's router
// buys permanent merge pain. They go at Phase C, with the rest of the
// legacy set, rather than being converted.
//
// Forwards-only: never add a lura import to a non-`legacy` file, and never
// add gin to one. The default build imports gin NOWHERE — assert it, do not
// assume it:
//
//	go list -deps ./cmd/gateway | grep gin-gonic    # empty
//
// Every gin transport lives in legacy_transports.go behind the tag, and gin
// remains in go.mod solely for the vendored KrakenD/Lura tree (internal/lura,
// internal/plugin) that the shipping image runs. It leaves go.mod when that
// tree is deleted at Phase C, and not before: `go list -deps -tags legacy`
// still reports it, because the shipped binary IS the legacy build.
package gateway
