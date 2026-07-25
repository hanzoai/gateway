// Copyright © 2026 Hanzo AI. Apache-2.0 License.

// Package gateway is the Hanzo Gateway edge: the JWT trust boundary
// (identity strip + mint), the host/path routing table, and the HIP-0106
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
// and of the standalone cmd/gateway binary. Mount installs the auth
// middleware, serves GET /_/gateway/healthz, and best-effort loads the
// routes table; it is called explicitly by cloud's composition root
// (cloud/apps.Wire), not by an init() and not via a global registry.
//
// # Build tags
//
// Two builds exist, and the one that SHIPS is `legacy`:
//
//	go build ./...               // default: no Lura/KrakenD; ZAP relay edge
//	go build -tags legacy ./...  // legacy: full Lura/KrakenD gin engine
//
// Makefile sets BUILD_TAGS ?= legacy and the Dockerfile runs `make build`,
// so ghcr.io/hanzoai/gateway is the legacy engine. The default build serves
// only /healthz until the HIP-0110 ZAP relay backends are live; see the
// rationale comment above BUILD_TAGS in the Makefile.
//
// Forwards-only: never add a lura/krakend import to a non-`legacy` file.
package gateway
