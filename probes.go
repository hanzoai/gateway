// Copyright © 2026 Hanzo AI. Apache-2.0 License.

// probes.go is the gateway's OWN HTTP surface — and it is the whole of it.
//
// The gateway is an edge. Every byte a customer sends it belongs to some other
// service, so the only doors this repo owns are the ones that answer a question
// about the gateway itself: is the process alive, is it ready to carry traffic.
// Everything else on the wire is a relay (HIP-0110, gate.go) or a proxy
// (routes.go) and is somebody else's contract.
//
// Those two doors are TYPED ops. They used to be three separate anonymous
// closures — one pair in BuildApp, one pair plus /metrics in cmd/gateway's
// health app, one lone healthz in Mount — each writing its own map literal, and
// each therefore free to answer a different shape. An untyped route appends
// nothing to the op registry, so all five were in no document: no OpenAPI
// operation, no MCP tool, no CLI command, no generated SDK method. A probe that
// is in no document is a probe an operator cannot discover, and five spellings
// of one answer is a shape that eventually disagrees with itself.
//
// One declaration, mounted at every place the gateway becomes an HTTP server:
//
//	BuildApp                 (HIP-0110 relay's :8080 liveness surface)
//	buildHealthApp           (cmd/gateway's :8081 k8s listener)
//	Mount + /_/gateway       (HIP-0106 unified-binary trust boundary)
//
// /metrics is deliberately NOT here — see MountMetrics.
package gateway

// zipdoc lifts the prose off each op and its In/Out fields into zipdoc_gen.go,
// which is the ONLY way a comment reaches the published document and the MCP
// tool list — Go drops comments at compile time.
//
//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

import (
	"context"
	"net/http"

	"github.com/zap-proto/zip"
)

// ServiceName is what a probe calls this service. One constant, so the answer
// is the same at all three mount points and an operator reading a probe body
// never has to work out which listener replied.
const ServiceName = "gateway"

// ProbeIn is the input of a probe: none. A liveness answer that depended on
// something the caller sent would not be a liveness answer.
type ProbeIn struct{}

// ProbeOut is what every gateway probe answers.
type ProbeOut struct {
	// Status is "ok" from the liveness probe and "ready" from the readiness
	// probe. It is the field a scraper reads when it reads the body at all;
	// orchestrators read the status code.
	Status string `json:"status"`
	// Service names the service that answered — always "gateway", including on
	// the separate k8s health listener, because the listener is a deployment
	// detail and the service is what the operator asked about.
	Service string `json:"service"`
}

// Probes registers the liveness and readiness ops at the ROOT of app — where a
// standalone process serves them, and where every orchestrator looks.
//
// Both of the standalone binary's listeners call it (the public :8080 relay
// surface and the :8081 k8s listener), so the two cannot answer differently
// about one process.
func Probes(app *zip.App) {
	zip.Get(app, "/healthz", healthz)
	zip.Get(app, "/readyz", readyz)
}

// MountProbes registers the SAME two ops under the gateway's reserved prefix,
// which is where they belong inside the unified cloud binary: there the root
// /healthz is the BINARY's, answered by whichever subsystem the composition
// root gives it to, and a co-resident subsystem that claimed it would be
// answering for the whole process.
//
// `/_/` rather than `/v1/` because these are the gateway's own doors, not
// product surface — the gateway is plumbing, and plumbing earns no version
// prefix.
//
// The two registrations are spelled out rather than sharing one loop over a
// prefix, because the PATH is the op's identity: every projection — the OpenAPI
// document, the MCP tool list, the CLI, a generated SDK — keys on it, and a
// prefix arriving as a parameter is a path no generator can resolve at the
// point of declaration.
func MountProbes(app *zip.App) {
	g := app.Group("/_/gateway")
	zip.Get(g, "/healthz", healthz)
	zip.Get(g, "/readyz", readyz)
}

// healthz reports that the gateway process is running and answering HTTP.
//
// It deliberately consults NOTHING — not the ZAP node, not a backend peer, not
// the JWKS cache. A liveness probe that fails when a dependency blinks gets a
// healthy process restarted and turns one outage into two. The relay degrades
// per-request when a backend is absent (see the lazy picker); it does not stop
// being alive.
func healthz(context.Context, *ProbeIn) (*ProbeOut, error) {
	return &ProbeOut{Status: "ok", Service: ServiceName}, nil
}

// readyz reports that the gateway is ready to carry traffic.
//
// Same answer as liveness by construction: the gateway holds no per-tenant
// state, warms no cache it needs before the first request, and dials its
// backends lazily on first use — so there is no interval during which the
// process is up and not yet ready. Readiness is a SEPARATE door rather than an
// alias because the deployment asks the two questions separately, and the day
// this service acquires something to warm, the widening happens here and
// nowhere else.
func readyz(context.Context, *ProbeIn) (*ProbeOut, error) {
	return &ProbeOut{Status: "ready", Service: ServiceName}, nil
}

// MountMetrics registers /metrics, the ONE route in this repo that is
// deliberately not a typed op.
//
// Prometheus' exposition format is line-oriented text, and a typed op answers
// JSON — the In/Out types ARE the contract, so declaring one here would put a
// JSON schema in the document for a route that has never sent JSON. That is
// worse than being absent from the document: an SDK generated from it would not
// work. So it stays an untyped route with the reason written next to it, which
// is the whole cost of the escape hatch and the reason it is countable.
//
// The body is a stub. The real collector is installed by the telemetry
// middleware when GATEWAY_METRICS_ENABLED=true; this keeps the path answering
// for scrapers when telemetry is off (dev/local) rather than 404ing at them.
func MountMetrics(app *zip.App) {
	app.Get("/metrics", func(c *zip.Ctx) error {
		c.SetHeader("Content-Type", "text/plain; version=0.0.4")
		return c.String(http.StatusOK, "# gateway up\n")
	})
}
