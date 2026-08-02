// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package gateway

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	luxlog "github.com/luxfi/log"
	zaplib "github.com/luxfi/zap"
)

// TestBuildApp_IsProbesAndNothingElse pins the HIP-0110 relay's HTTP surface.
//
// The relay's real work is on the ZAP node; the :8080 listener exists so the
// process has a liveness door. That makes the ROUTE COUNT a contract: the day
// somebody adds an HTTP route here, the gateway has quietly stopped being a
// pure relay and grown a second, unreviewed edge. This fails when that happens.
//
// It also pins the other half — every route this app carries is a TYPED op, so
// there is nothing on the public listener that is in no document.
func TestBuildApp_IsProbesAndNothingElse(t *testing.T) {
	node := zaplib.NewNode(zaplib.NodeConfig{NodeID: "probes-test", Port: 0, NoDiscovery: true})
	if err := node.Start(); err != nil {
		t.Fatalf("zap node start: %v", err)
	}
	t.Cleanup(node.Stop)

	app, err := BuildApp(RouterDeps{Logger: luxlog.New("test"), ZAPNode: node})
	if err != nil {
		t.Fatalf("BuildApp: %v", err)
	}

	d := app.Declaration()
	const wantRoutes, wantOps = 2, 2
	if len(d.Routes) != wantRoutes {
		t.Errorf("relay HTTP routes: got %d want %d — %+v", len(d.Routes), wantRoutes, d.Routes)
	}
	if len(d.Ops) != wantOps {
		t.Errorf("typed ops: got %d want %d — %+v", len(d.Ops), wantOps, d.Ops)
	}
	if len(d.Routes) != len(d.Ops) {
		t.Errorf("the relay surface carries %d untyped route(s); it should carry none",
			len(d.Routes)-len(d.Ops))
	}

	for path, want := range map[string]string{"/healthz": "ok", "/readyz": "ready"} {
		resp, err := app.Fiber().Test(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d want 200", path, resp.StatusCode)
		}
		var out ProbeOut
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("%s decode: %v", path, err)
		}
		if out.Status != want || out.Service != ServiceName {
			t.Fatalf("%s: got %+v want status=%q service=%q", path, out, want, ServiceName)
		}
	}
}

// TestProbes_OneAnswerEverywhere is the DRY assertion behind probes.go: the
// three places the gateway becomes an HTTP server answer the same probe with
// the same body, because there is one declaration rather than three literals.
//
// Asserted on the ops themselves, so it holds however they are mounted.
func TestProbes_OneAnswerEverywhere(t *testing.T) {
	live, err := healthz(t.Context(), &ProbeIn{})
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	ready, err := readyz(t.Context(), &ProbeIn{})
	if err != nil {
		t.Fatalf("readyz: %v", err)
	}
	if live.Status != "ok" || live.Service != ServiceName {
		t.Errorf("healthz: got %+v", live)
	}
	if ready.Status != "ready" || ready.Service != ServiceName {
		t.Errorf("readyz: got %+v", ready)
	}
}
