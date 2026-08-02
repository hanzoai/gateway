// Copyright © 2026 Hanzo AI. Apache-2.0 License.

// Package gateway is the Hanzo Gateway edge: the JWT trust boundary
// (identity strip + write), the host/path routing table, and the HIP-0106
// in-process mount surface consumed by the unified cloud binary.
//
// # Mount
//
// The canonical entrypoint is Mount, in mount.go at the module root:
//
//	func Mount(app *zip.App, deps cloud.Deps) error
//
// It carries NO build tag — it compiles in the default build. Consequently
// github.com/hanzoai/cloud is an unconditional dependency of this package
// and of the standalone cmd/gateway binary. Mount installs the native zip
// trust boundary (zipAuth), serves the typed probe pair under /_/gateway,
// and best-effort loads the routes table; it is called explicitly by cloud's
// composition root (cloud/apps.Wire), not by an init() and not via a global
// registry.
//
// # One policy, two HTTP transports
//
// The ALLOW/DENY ladder — strip, route class, public allowlists, token
// extraction, JWT validation, the identity write, the balance gate — is
// authGate.admit in authpolicy.go, and it knows about no framework. The gin
// middleware (auth_middleware.go, for the legacy Lura edge) and the native
// zip handler (zipAuth, for the unified binary) are each a dozen lines over
// it, so the two edges cannot admit different requests.
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
// add gin to one — the default build imports gin only through the three
// files that still carry the legacy edge's transports (auth_middleware.go,
// routes.go, widget_security.go), each consumed solely by legacy_engine.go.
// No default-build code path constructs a gin engine.
package gateway
