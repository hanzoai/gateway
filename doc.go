// Copyright © 2026 Hanzo AI. Apache-2.0 License.

// Package gateway is the HIP-0106 unified-binary mount surface for
// the Hanzo Gateway subsystem.
//
// The mount logic ships under the `cloud` build tag so the standalone
// cmd/gateway binary (vendor-mode, KrakenD-based, ghcr.io/hanzoai/gateway)
// builds without pulling hanzoai/cloud + hanzoai/zip into its
// dependency tree. Build with `-tags=cloud` to compile the Mount.
//
// See pkg/gateway/mount.go for the canonical
//
//	func Mount(app *zip.App, deps cloud.Deps) error
//
// signature and the init() callsite that registers ("gateway", order=80)
// in cloud.Registry.
package gateway
